# libfiowrapper

This library was created to help fuzzing application that are reading data from the file. It hooks file calls and replaces it with memory access.

Two libraries are available:

libfioinfo.so - this library just collects the statistics of different file calls that are used in the application

libfiowrapper.so - this library is used to replace file function calls with just memory access.

## Building
To build just run:
```
make
```

To display more information build debug version:
```
make debug
```

The demo applications are available inside the ```./examples``` directory. To build them just run:
```
cd ./examples/demo
make
```

## Running Demo Apps
The examples\demo directory, after build, will containe 3 application:
- info-demo - this application is just compailed with the clang. 
- file-fuzz-demo, file-fuzz-demo-posix - these applications are compiled with afl-clang-fast. They can be used to run fuzzing with simple input file.
- per-fuzz-demo, per-fuzz-demo-posix - these applications are compiled with the persistent mode.
- mem-fuzz-demo, mem-fuzz-demo-posix - these applicaitons are compiled with persistend mode with shared memory the libfiowrapper - it hooks all the f* stdio and posix file functions.

Bellow commands needs to be run from the examples/demo directory.

To collect information:
```
LD_PRELOAD=../../libfioinfo.so ./info-demo ./input/sample
===========================================
                libfioinfo
Version: 0.3
Author: Marek Zmysłowski
===========================================

one
two
three
===========================================
        File calls statistics:
fopen:  1
fwrite: 0 - unlocked: 0
fputc:  0 - unlocked: 0
fputs:  0 - unlocked: 0
fread:  0 - unlocked: 0
fgetc:  4 - unlocked: 0
fgets:  0 - unlocked: 0
fseek:  0
ftell:  0
fclose: 1

open:   0
read:   0
write:  0
lseek:  0
close:  0
===========================================

```

For the regular fuzzing with files run the file-fuzz-demo:
```
afl-fuzz -i ./input -o ./output -- ./file-fuzz-demo @@
```

For the persistent fuzzing run the per-fuzz-demo:
```
afl-fuzz -i ./input -o ./output -- ./per-fuzz-demo @@
```
For the persistent fuzzing with shared memory first the LD_LIBRARY_PATH needs to be set for the directory where the libfiowrapper.so is located.
```
export LD_LIBRARY_PATH=../../
afl-fuzz -i ./input -o ./output -- ./mem-fuzz-demo @@
```
## Modifing code
The code needs to be modify by adding few calls from the library. Just after __AFL_FUZZ_INIT add two function declarations:
```
__AFL_FUZZ_INIT();
#ifdef __cplusplus
extern "C" void set_memory_size(ssize_t size);
extern "C" void set_memory_ptr(unsigned char *buffer);
#else
extern void set_memory_size(ssize_t size);
extern void set_memory_ptr(unsigned char *buffer);
#endif
```

Before the AFL loop initialize the memory pointer:
```
set_memory_ptr(__AFL_FUZZ_TESTCASE_BUF);
```

Each iteration, the size needs to be set:
```
  while (__AFL_LOOP(1000)) {
    // Set the file size.
    set_memory_size(__AFL_FUZZ_TESTCASE_LEN);
```
## Real Live Example 
### libpng
To build libpng as an example please read [examples/libpng/README.md](examples/libpng)

## Questions and Feedback
If you have any questions or feedback, please send me an email to marekzmyslowski@poczta.onet.pl
