# -------------------------------------------------------------------------
#                     The CodeChecker Infrastructure
#   This file is distributed under the University of Illinois Open Source
#   License. See LICENSE.TXT for details.
# -------------------------------------------------------------------------
''''''
import os
import sys
import signal
import subprocess
import ntpath
import re
import fnmatch
import math
import linecache

from codechecker_lib import client
from codechecker_lib import logger
from codechecker_lib import analyzer_env
from codechecker_lib import plist_parser

LOG = logger.get_new_logger('ANALYZER')


class StaticAnalyzer(object):
    ''''''
    def __init__(self, context):
        self._context = context

        # Load all plugin from plugin directory
        plugin_dir = os.path.join(context.package_root, context.checker_plugin)
        self._plugins = [os.path.join(plugin_dir, f)
                         for f in os.listdir(plugin_dir)
                         if os.path.isfile(os.path.join(plugin_dir, f))]

        self._config = None
        self._skip = []
        self._workspace = ''
        self._mode = 'plist-multi-file'
        self._env = analyzer_env.get_check_env(context.path_env_extra,
                                               context.ld_lib_path_extra)

        self._checkers_list = []

        self._disabled_checkers = set()

        self._disabled_checkers = self._disabled_checkers.union(
            self._context.env_disabled_checkers)

        self._cmd = []
        self._cmd.append(self._context.compiler_bin)

        # if logger.get_log_level() == logger.DEBUG:
        #    self._cmd.append('-v')

        if len(self._context.compiler_resource_dirs) > 0:
            for inc_dir in self._context.compiler_resource_dirs:
                self._cmd.append('-resource-dir')
                self._cmd.append(inc_dir)
                self._cmd.append('-isystem')
                self._cmd.append(inc_dir)

        self._cmd.append('-c')

        # self._cmd.append('-Xclang')
        self._cmd.append('--analyze')

        # turn off clang hardcoded checkers list
        self._cmd.append('--analyzer-no-default-checks')

        for plugin in self._plugins:
            self._cmd.append("-Xclang")
            self._cmd.append("-load")
            self._cmd.append("-Xclang")
            self._cmd.append(plugin)

        if self._plugins:
            self._cmd.append('-Xclang')
            self._cmd.append('-plugin')
            self._cmd.append('-Xclang')
            self._cmd.append('checkercfg')

        self._cmd.append('-Xclang')
        self._cmd.append('-analyzer-opt-analyze-headers')
        self._cmd.append('-Xclang')
        self._cmd.append('-analyzer-output=' + self._mode)

        if self._context.compiler_sysroot:
            self._cmd.append('--sysroot')
            self._cmd.append(self._context.compiler_sysroot)

        for path in self._context.extra_system_includes:
            self._cmd.append('-isystem')
            self._cmd.append(path)

        for path in self._context.extra_includes:
            self._cmd.append('-I')
            self._cmd.append(path)

    # properties:
    @property
    def checkers(self):
        return self._checkers_list

    @checkers.setter
    def checkers(self, value):
        self._checkers_list.extend(value)

    @property
    def workspace(self):
        return self._workspace

    @workspace.setter
    def workspace(self, value):
        self._workspace = value

    @property
    def config(self):
        return self._config

    @property
    def cmd(self):
        for item in self._cmd:
            yield item

    @property
    def env(self):
        return self._env

    @property
    def run_id(self):
        return self._context.run_id

    @property
    def module_id(self):
        return self._context.module_id

    @property
    def severity_map(self):
        return self._context.severity_map

    @property
    def has_plugin(self):
        return len(self._plugins) != 0

    # public:
    def get_checker_list(self):
        command = [self._context.compiler_bin, "-cc1"]
        for plugin in self._plugins:
            command.append("-load")
            command.append(plugin)
        command.append("-analyzer-checker-help")

        result = subprocess.Popen(command,
                                  bufsize=-1,
                                  env=self._env,
                                  stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE)
        (stdout, stderr) = result.communicate()

        return stdout

    def add_config(self, connection, filepath):
        ''''''
        self._config = filepath
        if os.path.exists(filepath):
            client.send_config(connection, filepath)

    def add_skip(self, connection, filepath):
        ''''''
        if os.path.exists(filepath):
            orig_skiplist = get_skiplist(filepath)
            skiplist_with_comment = {}
            for line in orig_skiplist:
                if len(line) < 2 or line[0] not in ['-', '+']:
                    LOG.warning("Skipping malformed skipfile pattern: " + line)
                    continue

                # FIXME temporarly empty comment is set
                # should be read from the skip file
                skiplist_with_comment[line] = ''

                rexpr = re.compile(fnmatch.translate(line[1:].strip() + '*'))
                self._skip.append((line[0], rexpr))

            connection.add_skip_paths(skiplist_with_comment)

    def should_skip(self, source):
        '''Should the analyzer skip the given source file?'''
        for sign, rexpr in self._skip:
            if rexpr.match(source):
                return sign == '-'
        return False


def get_skiplist(file_name):
    '''Read skip file and return with its content in a list.'''
    with open(file_name, 'r') as skip_file:
        return [line.strip() for line in skip_file if line != '']

def _run_action(analyzer, action, on_result):
    '''
    Runs clang for all source file in the given action using the given analyzer.

    The last paramater is a callback function (on_result) with a keyword
    paramater. The following keyword paramater are forwarded:
        - check_command (str)
        - report_plist  (str, [path])
        - source_file   (str, [path])
        - err_code      (int)
        - err_message   (str)

    The callback should return an error code (zero means non error). The result
    of _run_action is the first non-zero return code or 0 if all callback call
    returned zero.
    '''

    def signal_handler(*args, **kwargs):
        # Clang does not kill its child processes, so I have to
        try:
            g_pid = result.pid
            os.killpg(g_pid, signal.SIGTERM)
        finally:
            sys.exit(os.EX_OK)

    signal.signal(signal.SIGINT, signal_handler)
    current_cmd = list(analyzer.cmd)

    for checker_name, enabled in analyzer.checkers:
        if enabled:
            current_cmd.append('-Xclang')
            current_cmd.append('-analyzer-checker=' + checker_name)
        else:
            current_cmd.append('-Xclang')
            current_cmd.append('-analyzer-disable-checker')
            current_cmd.append('-Xclang')
            current_cmd.append(checker_name)

    current_cmd.extend(action.analyzer_options)

    # Add checker config
    if analyzer.config and analyzer.has_plugin:
        current_cmd.append('-Xclang')
        current_cmd.append('-plugin-arg-checkercfg')
        current_cmd.append('-Xclang')
        current_cmd.append(analyzer.config)

    # Set lang
    current_cmd.append('-x')
    current_cmd.append(action.lang)

    result_code = 0
    for source in action.sources:
        if analyzer.should_skip(source):
            LOG.debug(source + ' is skipped.')
            continue

        source_name = source[source.rfind('/') + 1:].replace('.', '_')
        if not os.path.exists(analyzer.workspace):
            os.mkdir(analyzer.workspace)
        report_plist = os.path.join(analyzer.workspace,
                                    source_name + '_' +
                                    str(action.id) + '.plist')

        extender = list()
        extender.append('-o')
        extender.append(report_plist)
        extender.append(source)

        check_cmd = current_cmd + extender
        check_cmd_str = ' '.join(check_cmd)

        LOG.debug(' '.join(check_cmd))
        result = subprocess.Popen(check_cmd,
                                  bufsize=-1,
                                  env=analyzer.env,
                                  preexec_fn=os.setsid,
                                  stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE)
        (stdout, stderr) = result.communicate()
        LOG.debug(stdout)
        LOG.debug(stderr)

        failure = ''
        source_path, source_file = ntpath.split(source)
        if result.returncode != 0:
            failure = stdout + '\n' + stderr
            msg = 'Checking %s has failed.' % (source_file)
            LOG.debug(msg + '\n' + check_cmd_str + '\n' + failure)
            LOG.info(msg)

        tmp_result_code = on_result(check_command=check_cmd_str,
                                    report_plist=report_plist,
                                    source_file=source_file,
                                    err_code=result.returncode,
                                    err_message=failure)
        if result_code == 0:
            result_code = tmp_result_code
    return result_code

def run(analyzer, action):
    '''
    This function implements the "check" feature.
    '''

    with client.get_connection() as connection:
        def on_result(**args):
            check_command = args['check_command']
            action_id = connection.add_build_action(action.original_command,
                                                    check_command)

            err_code = args['err_code']
            if err_code == 0:
                client.send_plist_content(connection,
                                          args['report_plist'],
                                          action_id,
                                          analyzer.run_id,
                                          analyzer.severity_map,
                                          analyzer.should_skip)
                msg = 'Checking %s is done.' % (args['source_file'])
                LOG.debug(msg + '\n' + check_command)
                LOG.info(msg)

            connection.finish_build_action(action_id, args['err_message'])
            return err_code

        return _run_action(analyzer, action, on_result)

def run_quick_check(analyzer, action, print_steps=False, output=sys.stdout):
    '''
    This function implements the "quickcheck" feature.
    '''

    def format_location(event):
        pos = event.start_pos
        line = linecache.getline(pos.file_path, pos.line)
        if line == '':
            return line

        marker_line = line[0:(pos.col-1)]
        marker_line = ' '  * (len(marker_line) + marker_line.count('\t'))
        return '%s%s^' % (line.replace('\t', '  '), marker_line)

    def format_bug_event(event):
        pos = event.start_pos
        fname = os.path.basename(pos.file_path)
        return '%s:%d:%d: %s' % (fname, pos.line, pos.col, event.msg)

    def on_result(**args):
        LOG.debug(args['check_command'])

        source = args['source_file']
        plist = args['report_plist']
        if not os.path.isfile(plist):
            LOG.info('Checking %s failed!' % (source))
            return 1

        try:
            _, bugs = plist_parser.parse_plist(plist)
        except Exception:
            LOG.error('The generated plist is not valid!')
            return 1

        err_code = args['err_code']
        if len(bugs) > 0:
            output.write('%d defect(s) found while checking %s:\n\n' %
                         (len(bugs), source))
        else:
            output.write('No defects found in %s :-)\n' % source)
            return err_code

        index_format = '    %%%dd, ' % int(math.floor(math.log10(len(bugs)))+1)
        for bug in bugs:
            last_event = bug.get_last_event()
            output.write(format_bug_event(last_event))
            output.write('\n')
            output.write(format_location(last_event))
            output.write('\n')
            if print_steps:
                output.write('  Steps:\n')
                for index, event in enumerate(bug.events()):
                    output.write(index_format % (index + 1))
                    output.write(format_bug_event(event))
                    output.write('\n')
            output.write('\n')

        return err_code

    return _run_action(analyzer, action, on_result)
