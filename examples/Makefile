CC := clang
AFLCC := afl-clang-fast
LDFLAGS := -L../ -lfiowrapper

all: info-demo file-fuzz-demo mem-fuzz-demo
.PHONE: all

info-demo: demo-app.c
	$(CC) $(CFLAGS) $? -o $@

file-fuzz-demo: demo-app.c
	$(AFLCC) $(CFLAGS) $? -o $@

mem-fuzz-demo: demo-app.c
	$(AFLCC) $(CFLAGS) $(LDFLAGS) $? -DAFL_MEMORY -o $@

clean:
	rm -f info-demo file-fuzz-demo mem-fuzz-demo
