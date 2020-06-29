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


struct _FILE_
{
    // This definition is very limited for now
    FILE *_file;
    unsigned char *buffer;
    int read_pointer;
    ssize_t size;
    int memory_init;
} input_file;

// Deklaration for the structure that is used to be returned, when the file is opened.
FILE _file;

/*
 * Function sets the pointer for the shared memory from the AFL.
 */
void set_memory_ptr(unsigned char *buffer)
{
#ifdef DEBUG
    printf("set_memory_ptr:%p\n", buffer);
#endif
    input_file.size = 0;
    input_file.buffer = buffer;
    input_file.memory_init = 1;
    input_file.read_pointer = 0;
    input_file._file = &_file;
}

/*
 * Function sets the "size" of the shared memory.
 * The shared memory from AFL is fixed size. This is needed to understand where the input ends.
 */
void set_memory_size(ssize_t size)
{
#ifdef DEBUG
    printf("set_memory_size:%ld\n", size);
#endif
    input_file.size = size;
    input_file.read_pointer = 0;
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/*
 * fopen wrapper
 * 
 * If the memory was not initialized, the function will open file, copy it to memory and return fake structure.
 * If the memory was initialized, it just return the fake structure.
 */
FILE *fopen(const char *path, const char *mode)
{
#ifdef DEBUG
    printf("fopen - path:%s, mode:%s\n", path, mode);
#endif
    if (!input_file.memory_init)
    {
        input_file._file = _libc_fopen(path, mode);

        /* Get the number of bytes */
        _libc_fseek(input_file._file, 0L, SEEK_END);
        input_file.size = ftell(input_file._file);
        _libc_fseek(input_file._file, 0L, SEEK_SET);

#ifdef DEBUG
        printf("fopen - size:%ld\n", input_file.size);
#endif
        input_file.buffer = malloc(input_file.size + 1);
        _libc_fread(input_file.buffer, 1, input_file.size, input_file._file);
        input_file.read_pointer = 0;
    }
    return input_file._file;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/*
 * fwrite wrapper
 * 
 * If the stream is stdout, the size is returned.
 * 
 * Note: The other functionality is not implemented. I assume that the fuzzed application is not writing to the input
 */

size_t _fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream)
{
    if (stream == stdout)
        return size * nmemb;
    return 0;
}

size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream)
{
#ifdef DEBUG
    printf("fwrite - stream:%p, buffer:%p, size:%ld, nmemb:%ld\n", stream, ptr, size, nmemb);
#endif
    return _fwrite(ptr, size, nmemb, stream);
}

size_t fwrite_unlocked(const void *ptr, size_t size, size_t nmemb, FILE *stream)
{
#ifdef DEBUG
    printf("fwrite - stream:%p, buffer:%p, size:%ld, nmemb:%ld\n", stream, ptr, size, nmemb);
#endif
    return _fwrite(ptr, size, nmemb, stream);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/*
 *  fputc wrapper
 * 
 *  If the stream is stdout, the character is returned.
 * 
 *  Note: The other functionality is not implemented. I assume that the fuzzed application is not writing to the input
 */
int _fputc(int character, FILE *stream)
{
    if (stream == stdout)
        return character;

    return EOF;
}

int fputc(int character, FILE *stream)
{
#ifdef DEBUG
    printf("fputs - stream:%p, character:%c \n", stream, character);
#endif
    return _fputc(character, stream);
}

int fputc_unlocked(int character, FILE *stream)
{
#ifdef DEBUG
    printf("fputs_unlocked - stream:%p, character:%c \n", stream, character);
#endif
    return _fputc(character, stream);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/*
 *  fputs wrapper
 * 
 *  If the stream is stdout, the "1" is returned. 
 *  TODO: verify what exact value is returned on success.
 * 
 *  Note: The other functionality is not implemented. I assume that the fuzzed application is not writing to the input
 */
int _fputs(const char *str, FILE *stream)
{
    if (stream == stdout)
        return 1;
    
    return EOF;
}

int fputs(const char *str, FILE *stream)
{
#ifdef DEBUG
    printf("fputs - stream:%p, buffer:%s\n", stream, str);
#endif
    return _fputs(str, stream);
}

int fputs_unlocked(const char *str, FILE *stream)
{
#ifdef DEBUG
    printf("fputs_unlocked - stream:%p, buffer:%s\n", stream, str);
#endif
    return _fputs(str, stream);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/*
 * fread wrapper
 */
size_t _fread(void *ptr, size_t size, size_t nmemb, FILE *stream)
{
    size_t bytes_to_copy_left = size * nmemb;
    size_t bytes_copied = 0;
    while (bytes_to_copy_left)
    {
        if (input_file.read_pointer == input_file.size)
            break;
        ((char *)ptr)[bytes_copied] = input_file.buffer[input_file.read_pointer];
        input_file.read_pointer++;
        bytes_to_copy_left--;
        bytes_copied++;
    }
    return bytes_copied;
}

size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream)
{
#ifdef DEBUG
    printf("fread - stream:%p, buffer:%p, size:%ld, nmemb:%ld\n", stream, ptr, size, nmemb);
#endif
    return _fread(ptr, size, nmemb, stream);
}

size_t fread_unlocked(void *ptr, size_t size, size_t nmemb, FILE *stream)
{
#ifdef DEBUG
    printf("fread_unlocked - stream:%p, buffer:%p, size:%ld, nmemb:%ld\n", stream, ptr, size, nmemb);
#endif
    return _fread(ptr, size, nmemb, stream);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/*
 *  fgetc wrapper
 */
int _fgetc(FILE *stream)
{
    char c;
    if (input_file.read_pointer == input_file.size)
    {
        // This is the end of the file
        return EOF;
    }
    c = input_file.buffer[input_file.read_pointer];
    input_file.read_pointer++;
    return (unsigned char)c;
}

int fgetc(FILE *stream)
{
#ifdef DEBUG
    char c = _fgetc(stream);
    printf("fgetc - stream:%p, returned: %c\n", stream, c);
    return c;
#else
    return _fgetc(stream);
#endif
}

int fgetc_unlocked(FILE *stream)
{
#ifdef DEBUG
    char c = _fgetc(stream);
    printf("fgetc_unlocked - stream:%p, returned: %c\n", stream, c);
    return c;
#else
    return _fgetc(stream);
#endif
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/*
 *  fgets wrapper
 * 
 *  TODO: Fix the function.
 */
char *_fgets(char *str, int num, FILE *stream)
{
    return NULL;
}

char *fgets(char *str, int num, FILE *stream)
{
#ifdef DEBUG
    printf("fgets - stream:%p, str:%s, num:%d\n", stream, str, num);
#endif
    return _fgets(str, num, stream);
}

char *fgets_unlocked(char *str, int num, FILE *stream)
{
#ifdef DEBUG
    printf("fgets_unlocked - stream:%p, str:%s, num:%d\n", stream, str, num);
#endif
    return _fgets(str, num, stream);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/*
 * fseek wrapper
 * 
 * TODO: Make sure that the offsets are correct.
 */
int fseek(FILE *stream, long offset, int whence)
{
#ifdef DEBUG
    printf("fseek - stream:%p, offest:%ld, whence:%d\n", stream, offset, whence);
#endif
    switch (whence) {
	case SEEK_CUR:
    case SEEK_END:
        if (input_file.read_pointer + offset >= input_file.size || input_file.read_pointer + offset < 0)
        {
            input_file.read_pointer = input_file.size;
            return EOF;
        }
        else
        {
            input_file.read_pointer += offset;
            return 0;
        }
		break;
	case SEEK_SET:
        if (offset >= input_file.size)
            return EOF;
        else
            input_file.read_pointer += offset;
        break;
	default:
		return EOF;
	}
    return 0;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/*
 * fclose wrapper
 */
int fclose(FILE *stream)
{
#ifdef DEBUG
    printf("fclose - stream:%p\n", stream);
#endif
    return 0;
}

/*
 * Library constructor
 */
__attribute__((constructor)) static void init(void)
{
    _libc_fopen = (FILE * (*)(const char *path, const char *mode)) dlsym(RTLD_NEXT, "fopen");
    _libc_fwrite = (size_t(*)(const void *ptr, size_t size, size_t nmemb, FILE *stream))dlsym(RTLD_NEXT, "fwrite");
    _libc_fputc = (int (*)(int character, FILE *fp))dlsym(RTLD_NEXT, "fputc");
    _libc_fputs = (int (*)(const char *str, FILE *fp))dlsym(RTLD_NEXT, "fputs");
    _libc_fread = (size_t(*)(void *ptr, size_t size, size_t nmemb, FILE *stream))dlsym(RTLD_NEXT, "fread");
    _libc_fseek = (int (*)(FILE * stream, long offset, int whence)) dlsym(RTLD_NEXT, "fseek");
    _libc_fgetc = (int (*)(FILE * fp)) dlsym(RTLD_NEXT, "fgetc");
    _libc_fgets = (char *(*)(char *str, int num, FILE *fp))dlsym(RTLD_NEXT, "fgets");
    _libc_fclose = (int (*)(FILE * fp)) dlsym(RTLD_NEXT, "fclose");

    _libc_fwrite_unlocked = (size_t(*)(const void *ptr, size_t size, size_t nmemb, FILE *stream))dlsym(RTLD_NEXT, "fwrite_unlocked");
    _libc_fputc_unlocked = (int (*)(int character, FILE *fp))dlsym(RTLD_NEXT, "fputc_unlocked");
    _libc_fputs_unlocked = (int (*)(const char *str, FILE *fp))dlsym(RTLD_NEXT, "fputs_unlocked");
    _libc_fread_unlocked = (size_t(*)(void *ptr, size_t size, size_t nmemb, FILE *stream))dlsym(RTLD_NEXT, "fread_unlocked");
    _libc_fgetc_unlocked = (int (*)(FILE * fp)) dlsym(RTLD_NEXT, "fgetc_unlocked");
    _libc_fgets_unlocked = (char *(*)(char *str, int num, FILE *fp))dlsym(RTLD_NEXT, "fgets_unlocked");

    input_file.memory_init = 0;
}

/*
 * Library destructor
 */
__attribute__((destructor)) static void unload(void)
{
}