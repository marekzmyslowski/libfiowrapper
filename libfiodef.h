#ifndef __LIBFIODEF_H
#define __LIBFIODEF_H

#include <stdlib.h>
#include <stdio.h>

/*
 * THe pointer definitions for the original functions that are hooked.
 */

// Standard stdio functions
static FILE *(*_libc_fopen)(const char *path, const char *mode);
static FILE *(*_libc_fopen64)(const char *path, const char *mode);

static size_t (*_libc_fwrite)(const void *ptr, size_t size, size_t nmemb, FILE *stream);
static int (*_libc_fputc)(int character, FILE *stream);
static int (*_libc_fputs)(const char *str, FILE *stream);
static size_t (*_libc_fread)(void *ptr, size_t size, size_t nmemb, FILE *stream);
static int (*_libc_fgetc)(FILE *stream);
static char *(*_libc_fgets)(char *str, int num, FILE *stream);

static int (*_libc_fseek)(FILE *stream, long offset, int whence);
static int (*_libc_fseeko)(FILE *stream, off_t offset, int whence);
static int (*_libc_fseeko64)(FILE *stream, off64_t offset, int whence);

static long (*_libc_ftell)(FILE *stream);
static off_t (*_libc_ftello)(FILE *stream);
static off64_t (*_libc_ftello64)(FILE *stream);

static int (*_libc_fclose)(FILE *stream);

// Nonlocking stdio functions
static size_t (*_libc_fwrite_unlocked)(const void *ptr, size_t size, size_t nmemb, FILE *stream);
static int (*_libc_fputc_unlocked)(int character, FILE *stream);
static int (*_libc_fputs_unlocked)(const char *str, FILE *stream);
static size_t (*_libc_fread_unlocked)(void *ptr, size_t size, size_t nmemb, FILE *stream);
static int (*_libc_fgetc_unlocked)(FILE *stream);
static char *(*_libc_fgets_unlocked)(char *str, int num, FILE *stream);

// POSIX functions
static int (* _posix_open)(const char *pathname, int flags, ...);
static ssize_t (* _posix_read)(int fd, void *buf, size_t count);
static ssize_t (* _posix_write)(int fd, const void *buf, size_t count);
static off_t (* _posix_lseek)(int fd, off_t offset, int whence);

static int (* _posix_close)(int fd);


#endif