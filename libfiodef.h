#ifndef __LIBFIODEF_H
#define __LIBFIODEF_H

#include <stdlib.h>
#include <stdio.h>

/*
 * THe pointer definitions for the original functions that are hooked.
 */

// Standard stdio functions
static FILE *(*_libc_fopen)(const char *path, const char *mode);
static size_t (*_libc_fwrite)(const void *ptr, size_t size, size_t nmemb, FILE *stream);
static int (*_libc_fputc)(int character, FILE *fp);
static int (*_libc_fputs)(const char *str, FILE *fp);
static size_t (*_libc_fread)(void *ptr, size_t size, size_t nmemb, FILE *stream);
static int (*_libc_fgetc)(FILE *fp);
static char *(*_libc_fgets)(char *str, int num, FILE *fp);
static int (*_libc_fseek)(FILE *stream, long offset, int whence);
static int (*_libc_fclose)(FILE *fp);

// Nonlocking stdio functions
static size_t (*_libc_fwrite_unlocked)(const void *ptr, size_t size, size_t nmemb, FILE *stream);
static int (*_libc_fputc_unlocked)(int character, FILE *fp);
static int (*_libc_fputs_unlocked)(const char *str, FILE *fp);
static size_t (*_libc_fread_unlocked)(void *ptr, size_t size, size_t nmemb, FILE *stream);
static int (*_libc_fgetc_unlocked)(FILE *fp);
static char *(*_libc_fgets_unlocked)(char *str, int num, FILE *fp);


#endif