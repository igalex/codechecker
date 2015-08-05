/**
 * -------------------------------------------------------------------------
 *                     The CodeChecker Infrastructure
 *   This file is distributed under the University of Illinois Open Source
 *   License. See LICENSE.TXT for details.
 * -------------------------------------------------------------------------
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <linux/limits.h>
#include <dlfcn.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdbool.h>
#include <paths.h>
#include <elf.h>

#include "ldlogger-hooks.h"

#define CC_LOGGER_MAX_ARGS 2048

#define CC_LOGGER_CALL_EXEC(funName_, arglist, ...) \
  tryLog(__VA_ARGS__); \
  { \
    unsetLDPRELOAD(__VA_ARGS__); \
    typedef int (*FunType) arglist; \
    FunType fun = (FunType) dlsym(RTLD_NEXT, #funName_); \
    if (!fun) \
    { \
      return -1; \
    } \
    return (*fun)( __VA_ARGS__ ); \
  }

static void unsetLDPRELOAD(const char* const filename_, ...)
{
  char ldd[] = "ldd";
  const char* pos = strstr(filename_, ldd);
  if (pos)
  {
    unsigned int pos_number = pos-filename_;
    unsigned int prefix_length = strlen(filename_)-strlen(ldd);
    /* is there /ldd suffix in filename? or is filename equal ldd? */
    if ((prefix_length == pos_number) && ( pos_number == 0 || (pos-1 && *--pos == '/')))
    {
      unsetenv("LD_PRELOAD");
    }
  }
}

/**
 * Reads the given file descriptor and if it seems to be a valid ELF binary, it
 * returns 1.
 *
 * @param fd a file descriptor to read
 * @return 1 if the file is an ELF binary, 0 if not, -1 on error.
 */
static int isElf(int fd)
{
  unsigned char e_ident[EI_NIDENT];
  ssize_t rs;

  rs = read(fd, e_ident, sizeof(e_ident));
  if (rs != sizeof(e_ident) || rs == -1)
  {
    return -1;
  }

  if (e_ident[EI_MAG0] == ELFMAG0 &&
      e_ident[EI_MAG1] == ELFMAG1 &&
      e_ident[EI_MAG2] == ELFMAG2 &&
      e_ident[EI_MAG3] == ELFMAG3)
  {
    return 1;
  }

  return 0;
}

/**
 * Resolves the given command and opens its executable.
 *
 * @param filename a command or a file path
 * @return an opened file descriptor or -1 on error.
 */
static int openCommandExecutable(const char* filename_)
{
  if (strchr(filename_, '/'))
  {
    /* easy case: it's a relative or absolute path */
    return open(filename_, O_RDONLY);
  }
  else
  {
    /* Let's resolve the command using the PATH env. var. */
    char buff[PATH_MAX];
    size_t cmdlen;

    const char* PATH = getenv("PATH");
    if (!PATH)
    {
      PATH = _PATH_DEFPATH;
    }

    cmdlen = strlen(filename_);
    do
    {
      size_t plen;
      int fd;
      const char* elemStart = PATH;

      /* Find the end of the PATH element */
      PATH = strchr(elemStart, ':');
      if (!PATH)
      {
        PATH = strchr(elemStart, '\0');
      }

      if (elemStart == PATH)
      {
        /* Double colons in $PATH means to search the current directory */
        buff[0] = '.';
        plen = 1;
      }
      else
      {
        /* Simple PATH elem */
        plen = PATH - elemStart;
        memcpy(buff, elemStart, plen);
      }

      if (plen + cmdlen + 2 > sizeof(buff))
      {
        /* The path is too long */
        continue;
      }

      buff[plen] = '/';
      memcpy(buff + plen + 1, filename_, cmdlen);
      buff[plen + cmdlen + 1] = '\0';

      if (access(buff, X_OK) != 0)
      {
        /* not an executable */
        continue;
      }

      fd = open(buff, O_RDONLY);
      if (fd != -1)
      {
        return fd;
      }
    } while (*PATH != '\0' && *(++PATH) != '\0');
  }

  return -1;
}

/**
 * Decides whether the given program should be logged or not.
 *
 * @param filename_ a command or a file path
 * @return non-zero if should log this command, 0 otherwise
 */
static int shouldLog(const char* filename_)
{
  int res = 0;
  int fd;
  const char* binOnly = getenv("CC_LOG_BIN_ONLY");

  if (!binOnly || binOnly[0] != '1')
  {
    return 1;
  }

  if (!filename_)
  {
    return 0;
  }

  fd = openCommandExecutable(filename_);
  if (fd == -1)
  {
    /* can't open: if we can't decide by file content, let it go */
    return 1;
  }

  if (isElf(fd) != 0)
  {
    /* It's an elf executable or we can't decide (error) */
    res = 1;
  }

  close(fd);

  return res;
}

/**
 * Tries to log an exec* call.
 *
 * @param origin_ the exec* function name.
 * @param filename_ the filename / command (see lookupPath_).
 * @param argv_ arguments.
 */
static void tryLog(
  const char* const filename_,
  char* const argv_[], ...)
{
  size_t i;
  const char* loggerArgs[CC_LOGGER_MAX_ARGS];

  if (!shouldLog(filename_))
  {
    return;
  }

  loggerArgs[0] = filename_;
  for (i = 0; argv_[i]; ++i)
  {
    loggerArgs[i+1] = argv_[i];
  }
  loggerArgs[i+1] = NULL;

  logExec(i+1, loggerArgs);
}

__attribute__ ((visibility ("default"))) int execv(const char* filename_, char* const argv_[])
{
  CC_LOGGER_CALL_EXEC(execv, (const char*, char* const*),
    filename_, argv_);
}

__attribute__ ((visibility ("default"))) int execve(const char* filename_, char* const argv_[], char* const envp_[])
{
  CC_LOGGER_CALL_EXEC(execve, (const char*, char* const*, char* const*),
    filename_, argv_, envp_);
}

__attribute__ ((visibility ("default"))) int execvp(const char* filename_, char* const argv_[])
{
  CC_LOGGER_CALL_EXEC(execvp, (const char*, char* const*),
    filename_, argv_);
}

#ifdef _GNU_SOURCE
__attribute__ ((visibility ("default"))) int execvpe(const char* filename_, char *const argv_[], char* const envp_[])
{
  CC_LOGGER_CALL_EXEC(execvpe, (const char*, char* const*, char* const*),
    filename_, argv_, envp_);
}
#endif
