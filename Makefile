
CC = clang
CFLAGS = -ldl -fPIC -shared

all: libfioinfo libfiowrapper
all: CFLAGS += -O3
.PHONY: all

debug: CFLAGS += -DDEBUG
debug: libfioinfo libfiowrapper
.PHONY: debug

libfioinfo: libfioinfo.c
	$(CC) $(CFLAGS) $? -o $@.so 

libfiowrapper: libfiowrapper.c
	$(CC) $(CFLAGS) $? -o $@.so 

clean:
	rm -f libfioinfo.so libfiowrapper.so