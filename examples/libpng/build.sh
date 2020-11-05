#!/bin/sh

# Clone the libpng directory
git clone https://git.code.sf.net/p/libpng/code libpng-code

# Build libpng
cd libpng-code
git apply ../libpng-nocrc.diff
mkdir afl-build
cd afl-build
CC=afl-clang-fast cmake ..
make
cd ../..

# Build harness files.
afl-clang-fast readpng-fiow.c -o readpng-fiow ./libpng-code/afl-build/libpng16.a -lz -lm -L../../ -lfiowrapper -I./libpng-code/afl-build -I./libpng-code
afl-clang-fast readpng-pers.c -o readpng-pers ./libpng-code/afl-build/libpng16.a -lz -lm -I./libpng-code/afl-build -I./libpng-code
afl-clang-fast readpng.c -o readpng ./libpng-code/afl-build/libpng16.a -lz -lm -I./libpng-code/afl-build -I./libpng-code

# Download corpus and reduce the file to size 10K
svn export https://github.com/mozillasecurity/fuzzdata.git/trunk/samples/png input-png
cd input-png
mv ./chrome/* ./
mv ./common/* ./
rm -rf ./chrome
rm -rf common
find ./ -type f -size +10k | xargs rm