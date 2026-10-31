CC ?= cc
CFLAGS ?= -std=c11 -O2 -Wall -Wextra -Wpedantic
LDLIBS ?= -lcrypto
.PHONY: all clean test
all: forge-kernel
forge-kernel: src/forge.c
	$(CC) $(CFLAGS) $< -o $@ $(LDLIBS)
test: forge-kernel
	python3 tests/smoke.py
clean:
	rm -f forge-kernel
