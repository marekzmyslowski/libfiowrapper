/*
 * File I/O Functions Info
 * This library provides the statistics what functions where used during the execution. 
 * 
 * Author: Marek Zmysłowski
 * Version: 0.1
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *      http://www.apache.org/licenses/LICENSE-2.0
 * This is the real deal: the program takes an instrumented binary and
 * attempts a variety of basic fuzzing tricks, paying close attention to
 * how they affect the execution path.
 * 
 */

#define _GNU_SOURCE

#include <dlfcn.h>

#include <stdlib.h>
#include <stdio.h>
#include "libfiodef.h"

//
// Variables holding statistics
//
// Standard
static int fopen_count;
static int fwrite_count;
static int fputc_count;
static int fputs_count;
static int fread_count;
static int fseek_count;

static int ftell_count;
static int fgetc_count;
static int fgets_count;
static int fclose_count;

// Nonlocking
static int fwrite_unlocked_count;
static int fputc_unlocked_count;
static int fputs_unlocked_count;
static int fread_unlocked_count;
static int fseek_unlocked_count;
static int fgetc_unlocked_count;
static int fgets_unlocked_count;

/*
 * fopen wrapper
 */
FILE *fopen(const char *path, const char *mode)
{
    fopen_count++;
#ifdef DEBUG
    printf("fopen - path:%s, mode:%s\n", path, mode);
#endif
    return _libc_fopen(path, mode);
}

FILE *fopen64(const char *path, const char *mode)
{
    fopen_count++;
#ifdef DEBUG
    printf("fopen - path:%s, mode:%s\n", path, mode);
#endif
    return _libc_fopen64(path, mode);    
}

/****************************************************************************************************
 * 
 *                                  Standard stdio function wrappers
 * 
 ****************************************************************************************************/

/*
 * fwrite wrapper
 */
size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream)
{
    if (stream != stderr && stream != stdout)
        fwrite_count++;
#ifdef DEBUG
    printf("fwrite - stream:%p, buffer:%p, size:%ld, nmemb:%ld\n", stream, ptr, size, nmemb);
#endif
    return _libc_fwrite(ptr, size, nmemb, stream);
}

/*
 *  fputc wrapper
 */
int fputc(int character, FILE *stream)
{
    if (stream != stderr && stream != stdout)
        fputc_count++;
#ifdef DEBUG
    printf("fputc - stream:%p, character:%x \n", stream, character);
#endif
    return _libc_fputc(character, stream);
}

/*
 *  fputs wrapper
 */
int fputs(const char *str, FILE *stream)
{
    if (stream != stderr && stream != stdout)
        fputs_count++;
#ifdef DEBUG
    printf("fputs - stream:%p, buffer:%s\n", stream, str);
#endif
    return _libc_fputs(str, stream);
}

/*
 * fread wrapper
 */
size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream)
{
    if (stream != stderr && stream != stdout)
        fread_count++;
#ifdef DEBUG
    printf("fread - stream:%p, buffer:%p, size:%ld, nmemb:%ld\n", stream, ptr, size, nmemb);
#endif
    return _libc_fread(ptr, size, nmemb, stream);
}

/*
 * fseek wrapper
 */
int fseek(FILE *stream, long offset, int whence)
{
    if (stream != stderr && stream != stdout)
        fseek_count++;
#ifdef DEBUG
    printf("fseek - stream:%p, offest:%ld, whence:%d\n", stream, offset, whence);
#endif
    return _libc_fseek(stream, offset, whence);
}

/*
 *  fgetc wrapper
 */
int fgetc(FILE *stream)
{
    if (stream != stderr && stream != stdout)
        fgetc_count++;
#ifdef DEBUG
    printf("fgetc - stream:%p\n", stream);
#endif
    return _libc_fgetc(stream);
}

/*
 *  fgets wrapper
 */
char *fgets(char *str, int num, FILE *stream)
{
    if (stream != stderr && stream != stdout)
        fgets_count++;
#ifdef DEBUG
    printf("fgets - stream:%p, buffer:%s, size:%d\n", stream, str, num);
#endif
    return _libc_fgets(str, num, stream);
}

/////////////////////////////////////////////////////////////////////////////////////////////////
/*
 * ftell wrapper
 */
long ftell(FILE *stream)
{
    if (stream != stderr && stream != stdout)
        ftell_count++;
#ifdef DEBUG
    printf("ftell - stream:%p\n", stream);
#endif
    return _libc_ftell(stream);
}

off_t ftello(FILE *stream)
{
    if (stream != stderr && stream != stdout)
        ftell_count++;
#ifdef DEBUG
    printf("ftello - stream:%p\n", stream);
#endif
    return _libc_ftello(stream);
}

off64_t ftello64(FILE *stream)
{
    if (stream != stderr && stream != stdout)
        ftell_count++;
#ifdef DEBUG
    printf("ftello64 - stream:%p\n", stream);
#endif
    return _libc_ftello64(stream);
}

/////////////////////////////////////////////////////////////////////////////////////////////////
/*
 * fclose wrapper
 */
int fclose(FILE *stream)
{
    if (stream != stderr && stream != stdout)
        fclose_count++;
#ifdef DEBUG
    printf("fclose - stream:%p\n", stream);
#endif
    return _libc_fclose(stream);
}

/****************************************************************************************************
 * 
 *                                  Nonlocking stdio function wrappers
 * 
 ****************************************************************************************************/

/*
 *  fwrite_unlocked wrapper
 */
#ifndef __OPTIMIZE__
size_t fwrite_unlocked(const void *ptr, size_t size, size_t nmemb, FILE *stream)
{
    if (stream != stderr && stream != stdout)
        fwrite_unlocked_count++;
#ifdef DEBUG
    printf("fwrite_unlocked - stream:%p, buffer:%p, size:%ld, nmemb:%ld\n", stream, ptr, size, nmemb);
#endif
    return _libc_fwrite_unlocked(ptr, size, nmemb, stream);
}
#endif
/*
 *  fputc_unlocked wrapper
 */
int fputc_unlocked(int character, FILE *stream)
{
    if (stream != stderr && stream != stdout)
        fputc_unlocked_count++;
#ifdef DEBUG
    printf("fputs_unlocked - stream:%p, character:%c \n", stream, character);
#endif
    return _libc_fputc_unlocked(character, stream);
}

/*
 *  fputs_unlocked wrapper
 */
int fputs_unlocked(const char *str, FILE *stream)
{
    if (stream != stderr && stream != stdout)
        fputs_unlocked_count++;
#ifdef DEBUG
    printf("fputs_unlocked - stream:%p, buffer:%s\n", stream, str);
#endif
    return _libc_fputs_unlocked(str, stream);
}

/*
 * fread_unlocked wrapper
 */
#ifndef __OPTIMIZE__
size_t fread_unlocked(void *ptr, size_t size, size_t nmemb, FILE *stream)
{
    if (stream != stderr && stream != stdout)
        fread_unlocked_count++;
#ifdef DEBUG
    printf("fread_unlocked - stream:%p, buffer:%p, size:%ld, nmemb:%ld\n", stream, ptr, size, nmemb);
#endif
    return _libc_fread_unlocked(ptr, size, nmemb, stream);
}
#endif
/*
 * fgetc_unlocked wrapper
 */
int fgetc_unlocked(FILE *stream)
{
    if (stream != stderr && stream != stdout)
        fgetc_unlocked_count++;
#ifdef DEBUG
    printf("fgetc_unlocked - stream:%p\n", stream);
#endif
    return _libc_fgetc_unlocked(stream);
}

/*
 *  fgets_unlocked wrapper
 */
char *fgets_unlocked(char *str, int num, FILE *stream)
{
    if (stream != stderr && stream != stdout)
        fgets_unlocked_count++;
#ifdef DEBUG
    printf("fgets_unlocked - stream:%p, buffer:%s, size:%d\n", stream, str, num);
#endif
    return _libc_fgets_unlocked(str, num, stream);
}

/*
 * Fuction prints the banner and the library info
 */
void show_banner()
{
    printf("===========================================\n");
    printf("\t\tlibfioinfo\n");
    printf("Version: 0.1\n");
    printf("Author: Marek Zmysłowski\n");
    printf("===========================================\n\n");
}

/*
 * Function that prints statistics of the function calls
 */
void show_results()
{
    printf("===========================================\n");
    printf("\tFile calls statistics:\n");
    printf("fopen:  %d\n", fopen_count);
    printf("fwrite: %d - unlocked: %d\n", fwrite_count, fwrite_unlocked_count);
    printf("fputc:  %d - unlocked: %d\n", fputc_count, fputc_unlocked_count);
    printf("fputs:  %d - unlocked: %d\n", fputs_count, fputs_unlocked_count);
    printf("fread:  %d - unlocked: %d\n", fread_count, fread_unlocked_count);
    printf("fgetc:  %d - unlocked: %d\n", fgetc_count, fgetc_unlocked_count);
    printf("fgets:  %d - unlocked: %d\n", fgets_count, fgets_unlocked_count);
    printf("fseek:  %d\n", fseek_count);
    printf("ftell:  %d\n", ftell_count);
    printf("fclose: %d\n", fclose_count);
    printf("===========================================\n");
}

/*
 * Library constructor
 */
__attribute__((constructor)) static void init(void)
{
    _libc_fopen = (FILE * (*)(const char *path, const char *mode)) dlsym(RTLD_NEXT, "fopen");
    _libc_fopen64 = (FILE * (*)(const char *path, const char *mode)) dlsym(RTLD_NEXT, "fopen64");

    _libc_fwrite = (size_t(*)(const void *ptr, size_t size, size_t nmemb, FILE *stream))dlsym(RTLD_NEXT, "fwrite");
    _libc_fputc = (int (*)(int character, FILE *fp))dlsym(RTLD_NEXT, "fputc");
    _libc_fputs = (int (*)(const char *str, FILE *fp))dlsym(RTLD_NEXT, "fputs");
    _libc_fread = (size_t(*)(void *ptr, size_t size, size_t nmemb, FILE *stream))dlsym(RTLD_NEXT, "fread");
    _libc_fgetc = (int (*)(FILE * fp)) dlsym(RTLD_NEXT, "fgetc");
    _libc_fgets = (char *(*)(char *str, int num, FILE *fp))dlsym(RTLD_NEXT, "fgets");

    _libc_fseek = (int (*)(FILE * stream, long offset, int whence)) dlsym(RTLD_NEXT, "fseek");
    _libc_fseeko = (int (*)(FILE * stream, off_t offset, int whence)) dlsym(RTLD_NEXT, "fseeko");
    _libc_fseeko64 = (int (*)(FILE * stream, off64_t offset, int whence)) dlsym(RTLD_NEXT, "fseeko64");

    _libc_ftell = (long (*)(FILE * fp)) dlsym(RTLD_NEXT, "ftell");
    _libc_ftello = (off_t (*)(FILE * fp)) dlsym(RTLD_NEXT, "ftello");
    _libc_ftello64 = (off64_t (*)(FILE * fp)) dlsym(RTLD_NEXT, "ftello64");

    _libc_fclose = (int (*)(FILE * fp)) dlsym(RTLD_NEXT, "fclose");

    _libc_fwrite_unlocked = (size_t(*)(const void *ptr, size_t size, size_t nmemb, FILE *stream))dlsym(RTLD_NEXT, "fwrite_unlocked");
    _libc_fputc_unlocked = (int (*)(int character, FILE *fp))dlsym(RTLD_NEXT, "fputc_unlocked");
    _libc_fputs_unlocked = (int (*)(const char *str, FILE *fp))dlsym(RTLD_NEXT, "fputs_unlocked");
    _libc_fread_unlocked = (size_t(*)(void *ptr, size_t size, size_t nmemb, FILE *stream))dlsym(RTLD_NEXT, "fread_unlocked");
    _libc_fgetc_unlocked = (int (*)(FILE * fp)) dlsym(RTLD_NEXT, "fgetc_unlocked");
    _libc_fgets_unlocked = (char *(*)(char *str, int num, FILE *fp))dlsym(RTLD_NEXT, "fgets_unlocked");

    fopen_count = 0;
    fwrite_count = 0;
    fputc_count = 0;
    fputs_count = 0;
    fread_count = 0;
    fgetc_count = 0;
    fgets_count = 0;
    fseek_count = 0;
    ftell_count = 0;
    fclose_count = 0;

    fwrite_unlocked_count = 0;
    fputc_unlocked_count = 0;
    fputs_unlocked_count = 0;
    fread_unlocked_count = 0;
    fgetc_unlocked_count = 0;
    fgets_unlocked_count = 0;

    show_banner();
}

/*
 * Library destructor
 */
__attribute__((destructor)) static void unload(void)
{
    show_results();
}