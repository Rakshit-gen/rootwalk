.PHONY: build test fuzz bench bench-go lint

build:
	go build -o rootwalk ./cmd/rootwalk

test:
	go test -race ./...

fuzz:
	go test ./dnsmsg -run '^$$' -fuzz FuzzUnpack -fuzztime 30s

bench:
	scripts/bench.sh

bench-go:
	go test -run '^$$' -bench . -benchmem ./dnsmsg ./resolver

lint:
	test -z "$$(gofmt -l .)"
	go vet ./...
