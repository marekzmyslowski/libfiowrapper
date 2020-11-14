CC := clang
AFLCC := afl-clang-fast
LDFLAGS := -L../../ -lfiowrapper

all: info-demo file-fuzz-demo mem-fuzz-demo per-fuzz-demo info-demo-posix file-fuzz-demo-posix mem-fuzz-demo-posix per-fuzz-demo-posix
.PHONE: all

info-demo: demo-app.c
	$(CC) $(CFLAGS) $? -o $@

file-fuzz-demo: demo-app.c
	$(AFLCC) $(CFLAGS) $? -o $@

per-fuzz-demo: demo-app.c
	$(AFLCC) $(CFLAGS)  $? -DAFL_PERSISTENT -o $@

mem-fuzz-demo: demo-app.c
	$(AFLCC) $(CFLAGS) $(LDFLAGS) $? -DAFL_MEMORY -o $@

info-demo-posix: demo-app-posix.c
	$(CC) $(CFLAGS) $? -o $@

file-fuzz-demo-posix: demo-app-posix.c
	$(AFLCC) $(CFLAGS) $? -o $@

per-fuzz-demo-posix: demo-app-posix.c
	$(AFLCC) $(CFLAGS)  $? -DAFL_PERSISTENT -o $@

mem-fuzz-demo-posix: demo-app-posix.c
	$(AFLCC) $(CFLAGS) $(LDFLAGS) $? -DAFL_MEMORY -o $@

clean:
	rm -f info-demo file-fuzz-demo mem-fuzz-demo per-fuzz-demo info-demo-posix file-fuzz-demo-posix mem-fuzz-demo-posix per-fuzz-demo-posix