/*
 * File I/O Functions Info
 * This library provides the statistics what functions where used during the execution. 
 * 
 * Author: Marek Zmysłowski
 * Version: 0.3
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
#include <string.h>

#include "libfiodef.h"

#define AFL_FILE_NAME ".cur_input"
struct _AFL_MEMORY_FILE_
{
    // This definition is very limited for now
    FILE *stream;
    unsigned char *buffer;
    int read_pointer;
    ssize_t size;
    int memory;
    int fd;
} afl_input_file;

// This is used to speed up the process of allocating the FILE structure for the AFL input file/
// This needs to be done as valid pointer to the FILE struct needs to be returned
// QUESTION: does this structur needs to contain any real values or can be zeroed as it caputer all f* calls
FILE _fake_file;

/*
 * Function sets the pointer for the shared memory from the AFL.
 */
void set_memory_ptr(unsigned char *buffer)
{
#ifdef DEBUG
    printf("set_memory_ptr:%p\n", buffer);
#endif
    afl_input_file.size = 0;
    afl_input_file.buffer = buffer;
    afl_input_file.memory = 1;
    afl_input_file.read_pointer = 0;
    afl_input_file.stream = &_fake_file;
    afl_input_file.fd = 0xFF;
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
    afl_input_file.size = size;
    afl_input_file.read_pointer = 0;
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/*
 * fopen wrapper
 * 
 * If the memory was not initialized, the function will open file, copy it to memory and return fake structure.
 * If the memory was initialized, it just return the fake structure.
 * 
 * TODO: Add fopen64 when requested. Investigate if requires.
 */
FILE *_fopen(const char *path, const char *mode)
{
#ifdef DEBUG
    printf("fopen - path:%s, mode:%s\n", path, mode);
#endif
    if (strstr(path, AFL_FILE_NAME) != NULL)
    {
        // AFL input file
        if (!afl_input_file.memory)
        {
#ifdef DEBUG
    printf("fopen - loading file into memory\n");
#endif    
            afl_input_file.stream = _libc_fopen(path, mode);
            /* Get the number of bytes */
            _libc_fseek(afl_input_file.stream, 0L, SEEK_END);
            afl_input_file.size = _libc_ftell(afl_input_file.stream);
            _libc_fseek(afl_input_file.stream, 0L, SEEK_SET);


#ifdef DEBUG
            printf("fopen - size:%ld\n", afl_input_file.size);
#endif
            afl_input_file.buffer = malloc(afl_input_file.size + 1);
            _libc_fread(afl_input_file.buffer, 1, afl_input_file.size, afl_input_file.stream);
            afl_input_file.read_pointer = 0;
        }
        return afl_input_file.stream;
    }
    // The other file is requested to be opened
    return _libc_fopen(path, mode);
}

FILE *fopen(const char *path, const char *mode)
{
    return _fopen(path, mode);
}

#if defined(_LARGEFILE64_SOURCE) && !defined(__APPLE__)
FILE *fopen64(const char *path, const char *mode)
{
    return _fopen(path, mode);
}
#endif
////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/*
 * fwrite wrapper
 * 
 * Currently the assumption is, that the data stored by the application are not used at all so 
 * it just fakes the data were written.
 * 
 * Note: The other functionality is not implemented. I assume that the fuzzed application is not writing to the input
 */

size_t _fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream)
{
    return size * nmemb;
}

size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream)
{
#ifdef DEBUG
    printf("fwrite - stream:%p, buffer:%p, size:%ld, nmemb:%ld\n", stream, ptr, size, nmemb);
#endif
    return _fwrite(ptr, size, nmemb, stream);
}

//
// fwrite_unlocked in optimized version is a preprocessor declaration that uses fputc_unlocked
//
#ifndef __OPTIMIZE__
size_t fwrite_unlocked(const void *ptr, size_t size, size_t nmemb, FILE *stream)
{
#ifdef DEBUG
    printf("fwrite - stream:%p, buffer:%p, size:%ld, nmemb:%ld\n", stream, ptr, size, nmemb);
#endif
    return _fwrite(ptr, size, nmemb, stream);
}
#endif
////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/*
 *  fputc wrapper
 * 
 *  The function fakes that the write operation was performed.
 * 
 *  Note: The other functionality is not implemented. I assume that the fuzzed application is not writing to the input.
 */
int _fputc(int character, FILE *stream)
{
    return character;
}

int fputc(int character, FILE *stream)
{
#ifdef DEBUG
    printf("fputc - stream:%p, character:0x%.2X\n", stream, character);
#endif
    return _fputc(character, stream);
}

int fputc_unlocked(int character, FILE *stream)
{
#ifdef DEBUG
    printf("fputc_unlocked - stream:%p, character:0x%.2X\n", stream, character);
#endif
    return _fputc(character, stream);
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/*
 *  fputs wrapper
 * 
 *  The function fakes that the write operation was performed.
 *  TODO: verify what exact value is returned on success.
 * 
 *  Note: The other functionality is not implemented. I assume that the fuzzed application is not writing to the input.
 */
int _fputs(const char *str, FILE *stream)
{
    return 1;
}

int fputs(const char *str, FILE *stream)
{
#ifdef DEBUG
    printf("fputs - stream:%p, buffer:%s\n", stream, str);
#endif
    return _fputs(str, stream);
}

//
// fputs_unlocked in optimized version is a preprocessor declaration that uses fputc_unlocked
//
#ifndef __OPTIMIZE__
int fputs_unlocked(const char *str, FILE *stream)
{
#ifdef DEBUG
    printf("fputs_unlocked - stream:%p, buffer:%s\n", stream, str);
#endif
    return _fputs(str, stream);
}
#endif
////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/*
 * fread wrapper
 */
size_t _fread(void *ptr, size_t size, size_t nmemb, FILE *stream)
{
    if (stream == afl_input_file.stream)
    {
        size_t bytes_to_copy_left = size * nmemb;
        size_t bytes_copied = 0;
        while (bytes_to_copy_left)
        {
            if (afl_input_file.read_pointer == afl_input_file.size)
                break;
            ((char *)ptr)[bytes_copied] = afl_input_file.buffer[afl_input_file.read_pointer];
            afl_input_file.read_pointer++;
            bytes_to_copy_left--;
            bytes_copied++;
        }
        return bytes_copied;
    }
    else
    {
        return _libc_fread(ptr, size, nmemb, stream);
    }
}

size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream)
{
#ifdef DEBUG
    printf("fread - stream:%p, buffer:%p, size:%ld, nmemb:%ld\n", stream, ptr, size, nmemb);
#endif
    return _fread(ptr, size, nmemb, stream);
}

//
// fread_unlocked in optimized version is a preprocessor declaration that uses fgetc_unlocked
//
#ifndef __OPTIMIZE__
size_t fread_unlocked(void *ptr, size_t size, size_t nmemb, FILE *stream)
{
#ifdef DEBUG
    printf("fread_unlocked - stream:%p, buffer:%p, size:%ld, nmemb:%ld\n", stream, ptr, size, nmemb);
#endif
    return _fread(ptr, size, nmemb, stream);
}
#endif
////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/*
 *  fgetc wrapper
 */
int _fgetc(FILE *stream)
{
    char c;
    if (stream == afl_input_file.stream)
    {
        if (afl_input_file.read_pointer == afl_input_file.size)
        {
            // This is the end of the file
            return EOF;
        }
        c = afl_input_file.buffer[afl_input_file.read_pointer];
        afl_input_file.read_pointer++;
        return (unsigned char)c;
    }
    else
    {
        return _libc_fgetc(stream);
    }
}

int fgetc(FILE *stream)
{
#ifdef DEBUG
    char c = _fgetc(stream);
    printf("fgetc - stream:%p, returned:0x%.2X\n", stream, c);
    return c;
#else
    return _fgetc(stream);
#endif
}

int fgetc_unlocked(FILE *stream)
{
#ifdef DEBUG
    char c = _fgetc(stream);
    printf("fgetc_unlocked - stream:%p, returned:0x%.2X\n", stream, c);
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
    if (stream == afl_input_file.stream)
    {
        switch (whence)
        {
        case SEEK_CUR:
        case SEEK_END:
            if (afl_input_file.read_pointer + offset >= afl_input_file.size || afl_input_file.read_pointer + offset < 0)
            {
                afl_input_file.read_pointer = afl_input_file.size;
                return EOF;
            }
            else
            {
                afl_input_file.read_pointer += offset;
                return 0;
            }
            break;
        case SEEK_SET:
            if (offset >= afl_input_file.size)
                return EOF;
            else
                afl_input_file.read_pointer = offset;
            return 0;
            break;
        default:
            return EOF;
        }
    }
    else
    {
        return _libc_fseek(stream, offset, whence);
    }
}

long ftell(FILE *stream)
{
#ifdef DEBUG
    printf("ftell - stream:%p\n", stream);
#endif
    if (stream == afl_input_file.stream)
    {
        return afl_input_file.read_pointer;
    }
    else
    {
        return _libc_ftell(stream);
    }
}
#if defined(_LARGEFILE64_SOURCE) && !defined(__APPLE__)
off_t ftello64(FILE *stream)
{
#ifdef DEBUG
    printf("ftello64 - stream:%p\n", stream);
#endif
    if (stream == afl_input_file.stream)
    {
        return (off_t)afl_input_file.read_pointer;
    }
    else
    {
        return _libc_ftello64(stream);
    }
}
#endif

////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/*
 * fclose wrapper
 */
int fclose(FILE *stream)
{
#ifdef DEBUG
    printf("fclose - stream:%p\n", stream);
#endif
    if (stream == afl_input_file.stream)
    {
        if (!afl_input_file.memory)
            return _libc_fclose(stream);
        else
            return 0;
    }
    else
        return _libc_fclose(stream);
}

// TODO Fix argument passing
int open(const char *pathname, int flags, ...)
{
#ifdef DEBUG
    printf("open - path:%s\n", pathname);
#endif
    if (strstr(pathname, AFL_FILE_NAME) != NULL)
    {
        if (!afl_input_file.memory)
        {
            // TODO Fix later
        }
        return afl_input_file.fd;
    }
    return _posix_open(pathname, flags);
}

ssize_t read(int fd, void *buf, size_t count)
{
#ifdef DEBUG
    printf("read - fd %d, buf:%p, count:%ld\n", fd, buf, count);
#endif
    if (fd == afl_input_file.fd)
    {
        size_t bytes_to_copy_left = count;
        size_t bytes_copied = 0;
        while (bytes_to_copy_left)
        {
            if (afl_input_file.read_pointer == afl_input_file.size)
                break;
            ((char *)buf)[bytes_copied] = afl_input_file.buffer[afl_input_file.read_pointer];
            afl_input_file.read_pointer++;
            bytes_to_copy_left--;
            bytes_copied++;
        }
        return bytes_copied;
    }
    else
    {
        return _posix_read(fd, buf, count);
    }
}

ssize_t write(int fd, const void *buf, size_t count)
{
#ifdef DEBUG
    printf("write - fd %d, buf:%p, count:%ld\n", fd, buf, count);
#endif
    return _posix_write(fd, buf, count);
}

off_t lseek(int fd, off_t offset, int whence)
{
#ifdef DEBUG
    printf("lseek - fd %d, offset:%ld, whence:%d\n", fd, offset, whence);
#endif
    if (fd == afl_input_file.fd)
    {
        switch (whence)
        {
        case SEEK_CUR:
        case SEEK_END:
            if (afl_input_file.read_pointer + offset >= afl_input_file.size || afl_input_file.read_pointer + offset < 0)
            {
                afl_input_file.read_pointer = afl_input_file.size;
                return EOF;
            }
            else
            {
                afl_input_file.read_pointer += offset;
                return 0;
            }
            break;
        case SEEK_SET:
            if (offset >= afl_input_file.size)
                return EOF;
            else
                afl_input_file.read_pointer = offset;
            return 0;
            break;
        default:
            return EOF;
        }
    }
    else
    {
        return _posix_lseek(fd, offset, whence);
    } 
}

int close(int fd)
{
#ifdef DEBUG
    printf("close - fd %d\n", fd);
#endif
    if (fd == afl_input_file.fd)
    {
        // TODO Fix this
        return 0;
    }
    else
        return _posix_close(fd);
}

/*
 * Library constructor
 */
__attribute__((constructor)) static void init(void)
{
    // TODO Remove unused functions
    _libc_fopen = (FILE * (*)(const char *path, const char *mode)) dlsym(RTLD_NEXT, "fopen");

    _libc_fwrite = (size_t(*)(const void *ptr, size_t size, size_t nmemb, FILE *stream))dlsym(RTLD_NEXT, "fwrite");
    _libc_fputc = (int (*)(int character, FILE *fp))dlsym(RTLD_NEXT, "fputc");
    _libc_fputs = (int (*)(const char *str, FILE *fp))dlsym(RTLD_NEXT, "fputs");
    _libc_fread = (size_t(*)(void *ptr, size_t size, size_t nmemb, FILE *stream))dlsym(RTLD_NEXT, "fread");
    _libc_fseek = (int (*)(FILE * stream, long offset, int whence)) dlsym(RTLD_NEXT, "fseek");
    _libc_ftell = (long (*)(FILE * stream)) dlsym(RTLD_NEXT, "ftell");
    _libc_fgetc = (int (*)(FILE * fp)) dlsym(RTLD_NEXT, "fgetc");
    _libc_fgets = (char *(*)(char *str, int num, FILE *fp))dlsym(RTLD_NEXT, "fgets");
    _libc_fclose = (int (*)(FILE * fp)) dlsym(RTLD_NEXT, "fclose");

#if defined(_LARGEFILE64_SOURCE) && !defined(__APPLE__)
    _libc_fopen64 = (FILE * (*)(const char *path, const char *mode)) dlsym(RTLD_NEXT, "fopen64");
    _libc_ftello64 = (off_t (*)(FILE * stream)) dlsym(RTLD_NEXT, "ftello64");
#endif

    _libc_fwrite_unlocked = (size_t(*)(const void *ptr, size_t size, size_t nmemb, FILE *stream))dlsym(RTLD_NEXT, "fwrite_unlocked");
    _libc_fputc_unlocked = (int (*)(int character, FILE *fp))dlsym(RTLD_NEXT, "fputc_unlocked");
    _libc_fputs_unlocked = (int (*)(const char *str, FILE *fp))dlsym(RTLD_NEXT, "fputs_unlocked");
    _libc_fread_unlocked = (size_t(*)(void *ptr, size_t size, size_t nmemb, FILE *stream))dlsym(RTLD_NEXT, "fread_unlocked");
    _libc_fgetc_unlocked = (int (*)(FILE * fp)) dlsym(RTLD_NEXT, "fgetc_unlocked");
    _libc_fgets_unlocked = (char *(*)(char *str, int num, FILE *fp))dlsym(RTLD_NEXT, "fgets_unlocked");

    _posix_open = (int (*)(const char *pathname, int flags, ...))dlsym(RTLD_NEXT, "open");
    _posix_read = (ssize_t (*)(int fd, void *buf, size_t count))dlsym(RTLD_NEXT, "read");
    _posix_write = (ssize_t (*)(int fd, const void *buf, size_t count))dlsym(RTLD_NEXT, "write");
    _posix_lseek = (off_t (*)(int fd, off_t offset, int whence))dlsym(RTLD_NEXT, "lseek");
    _posix_close = (int (*)(int fd))dlsym(RTLD_NEXT, "close");

    afl_input_file.memory = 0;
}

/*
 * Library destructor
 */
__attribute__((destructor)) static void unload(void)
{
}