This is libpng example.

## Building
The simple way is just to run the ```./build.sh``` script. It downloads libpng, applies patches, compiles and build the ```readpng.c``` application ready to fuzz.

```
export LD_LIBRARY_PATH=<path to directory with libfiowrapper.so>
afl-fuzz -i ./input-png/ -o ./output -- ./readpng @@
```
