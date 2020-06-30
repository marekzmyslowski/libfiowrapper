/*
   american fuzzy lop++ - persistent mode example
   --------------------------------------------

   Originally written by Michal Zalewski

   Copyright 2015 Google Inc. All rights reserved.

   Modifed: Marek Zmysłowski
   Copyright: 2020

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This file demonstrates the high-performance "persistent mode" that may be
   suitable for fuzzing certain fast and well-behaved libraries, provided that
   they are stateless or that their internal state can be easily reset
   across runs.

   To make this work, the library and this shim need to be compiled in LLVM
   mode using afl-clang-fast (other compiler wrappers will *not* work).

 */


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>

#ifdef AFL_MEMORY
__AFL_FUZZ_INIT();
extern void set_memory_size(ssize_t size);
extern void set_memory_ptr(unsigned char *buffer);
#endif



/* Main entry point. */

int main(int argc, char **argv) {

  ssize_t        len;                        /* how much input did we read? */
  unsigned char  *buf;                        /* test case buffer pointer    */
  FILE           *file;

  /* The number passed to __AFL_LOOP() controls the maximum number of
     iterations before the loop exits and the program is allowed to
     terminate normally. This limits the impact of accidental memory leaks
     and similar hiccups. */
#ifdef AFL_MEMORY
    // Set the memory pointer inside library.
    set_memory_ptr(__AFL_FUZZ_TESTCASE_BUF);


  while (__AFL_LOOP(1000)) {
    // Set the file size.
    set_memory_size(__AFL_FUZZ_TESTCASE_LEN);
#endif
#ifdef AFL_PERSISTENT
  __AFL_INIT();
  while (__AFL_LOOP(1000)) {
#endif
    file = fopen(argv[1], "r");
    if (fgetc(file) == 'f') {

      printf("one\n");
      if (fgetc(file) == 'o') {

        printf("two\n");
        if (fgetc(file) == 'o') {

          printf("three\n");
          if (fgetc(file) == '!') {

            printf("four\n");
            if (fgetc(file) == '!') {

              printf("five\n");
              if (fgetc(file) == '!') {

                printf("six\n");
                abort();

              }

            }

          }

        }

      }

    }
    fclose(file);
    /*** END PLACEHOLDER CODE ***/
#if defined AFL_MEMORY || defined AFL_PERSISTENT
  }
#endif
  /* Once the loop is exited, terminate normally - AFL will restart the process
     when this happens, with a clean slate when it comes to allocated memory,
     leftover file descriptors, etc. */

  return 0;

}

