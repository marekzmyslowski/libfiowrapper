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
- file-fuzz-demo - this application is compiled with afl-clang-fast. It can be used to run fuzzing with simple input file.
- per-fuzz-demo - this application is compiled with simple persistent mode.
- mem-fuzz-demo - this applicaiton is compiled with persistend mode with shared memory with the libfiowrapper library to hook all the f* stdio functions.

To collect information:
```
/research/libfiowrapper$ LD_PRELOAD=/research/libfiowrapper/libfioinfo.so ./examples/info-demo ./examples/input/sample
===========================================
                libfioinfo
Version: 0.1
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
fclose: 1

```
For the regular fuzzing with files run the file-fuzz-demo:
```
afl-fuzz -i ./input -o ./output -- ./examples/file-fuzz-demo @@
```

For the memory fuzzing first the LD_LIBRARY_PATH needs to be set for the directory where the libfiowrapper.so is located.
```
export LD_LIBRARY_PATH=./
afl-fuzz -i ./input -o ./output -- ./examples/mem-fuzz-demo @@
```
## Modifing code
The code needs to be modify by adding few calls from the library. Just after __AFL_FUZZ_INIT add two function declarations:
```
__AFL_FUZZ_INIT();
extern void set_memory_size(ssize_t size);
extern void set_memory_ptr(unsigned char *buffer);
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