
CC = clang
CFLAGS = -ldl -fPIC -shared

.PHONY: all debug demo examples help

help:
	@echo ''
	@echo ' usage: make [target]'
	@echo ''
	@echo '	release		- build release version of the libraries'
	@echo '	debug 		- build debug version of the libraries'
	@echo '	all 		- build everything (release, demo, example)'
	@echo '	demo 		- build demo applications'
	@echo '	examples	- build example applications'
	@echo '	clean		- clean libraries and demo applications'
	@echo ''

all: release demo examples

release: libfioinfo libfiowrapper
release: CFLAGS += -O3

debug: CFLAGS += -DDEBUG
debug: libfioinfo libfiowrapper

demo:
	$(MAKE) -C ./examples/demo

examples:
	cd ./examples/libpng; ./build.sh

libfioinfo: libfioinfo.c
	$(CC) $(CFLAGS) $? -o $@.so 

libfiowrapper: libfiowrapper.c
	$(CC) $(CFLAGS) $? -o $@.so 

clean:
	rm -f libfioinfo.so libfiowrapper.so
	$(MAKE) clean -C ./examples/demo