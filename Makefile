.PHONY: build test fuzz bench lint

build:
	go build -o rootwalk ./cmd/rootwalk

test:
	go test -race ./...

fuzz:
	go test ./dnsmsg -run '^$$' -fuzz FuzzUnpack -fuzztime 30s

bench:
	scripts/bench.sh

lint:
	test -z "$$(gofmt -l .)"
	go vet ./...
