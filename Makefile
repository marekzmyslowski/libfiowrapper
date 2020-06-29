
CC = clang
CFLAGS = -ldl -fPIC -shared

all: libfioinfo libfiowrapper
.PHONY: all

debug: CFLAGS += -DDEBUG
debug: all

libfioinfo: libfioinfo.c
	$(CC) $(CFLAGS) $? -o $@.so 

libfiowrapper: libfiowrapper.c
	$(CC) $(CFLAGS) $? -o $@.so 

clean:
	rm -f libfioinfo.so libfiowrapper.so