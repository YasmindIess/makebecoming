CC ?= cc
CFLAGS ?= -std=c11 -O2 -Wall -Wextra -Wpedantic
LDLIBS ?= -lcrypto
.PHONY: all clean test field
all: forge-kernel
forge-kernel: src/forge.c
	$(CC) $(CFLAGS) $< -o $@ $(LDLIBS)
field: forge-kernel
	./forge-kernel field examples/v2_1_verified.jsonl > field.json
test: forge-kernel
	python3 tests/test_r0.py
	python3 tests/test_store.py
	python3 tests/test_field.py
clean:
	rm -f forge-kernel
