.PHONY: build test check install icon clean

build:
	go build -o bin/gate ./cmd/gate
	go build -o bin/gates ./cmd/gates

test:
	go test ./...

check: build
	go vet ./...
	./bin/gates check

install: build
	./tools/install.sh

icon:
	swift tools/set-icon.swift "$(PWD)"

clean:
	rm -rf bin
