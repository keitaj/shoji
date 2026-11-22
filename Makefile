# Tools are looked up on PATH first, then in their default install locations.
export PATH := $(PATH):$(HOME)/.nargo/bin:$(HOME)/.bb
NARGO := $(shell command -v nargo || echo $(HOME)/.nargo/bin/nargo)
BB := $(shell command -v bb || echo $(HOME)/.bb/bb)
TARGET := noir-recursive

.PHONY: all fixtures circuit test test-circuit test-go bench clean

all: circuit test

# Mock CA + certificates in testdata/, and the Noir test fixtures. These are not
# in git: they are created on first use and reused afterwards.
fixtures:
	go run ./cmd/genfixtures

# Compile the circuit and write its verification key.
# (The circuit crate declares `mod fixtures` for its tests, so the file must exist.)
circuit: fixtures
	cd circuits && $(NARGO) compile
	mkdir -p circuits/target/vk
	$(BB) write_vk -b circuits/target/shoji.json -o circuits/target/vk -t $(TARGET)

test: test-circuit test-go

test-circuit: fixtures
	cd circuits && $(NARGO) test

# Needs `make circuit` first; the tests that need bb skip otherwise.
test-go: fixtures
	go test ./...

bench: circuit
	./scripts/bench.sh

clean:
	rm -rf circuits/target shoji.db
