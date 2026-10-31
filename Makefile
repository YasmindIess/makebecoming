CC ?= cc
CFLAGS ?= -std=c11 -O2 -Wall -Wextra -Wpedantic
LDLIBS ?= -lcrypto
.PHONY: all clean test field occlusion
all: forge-kernel forge-grant
forge-kernel: src/forge.c
	$(CC) $(CFLAGS) $< -o $@ $(LDLIBS)
forge-grant: src/forge-grant.c
	$(CC) $(CFLAGS) $< -o $@ $(LDLIBS)
field: forge-kernel
	./forge-kernel field examples/v2_1_verified.jsonl > field.json
occlusion: forge-kernel
	./forge-kernel occlude examples/v2_1_verified.jsonl > occlusion-public.json
test: forge-kernel forge-grant
	python3 tests/test_r0.py
	python3 tests/test_store.py
	python3 tests/test_field.py
	python3 tests/test_occlusion.py
	python3 tests/test_grants.py
clean:
	rm -f forge-kernel forge-grant
