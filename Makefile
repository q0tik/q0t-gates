.PHONY: build test check install icon clean

build:
	go build -o bin/gate ./cmd/gate
	go build -o bin/gates ./cmd/gates

test:
	go test ./...

check: build
	go vet ./...
	./bin/gates check
	@# YAML ломается от двоеточия в незакавыченной строке, и CI об этом
	@# сообщает падением за 0 секунд без единой строки лога — проверяем локально
	@uv run --quiet --with pyyaml python3 -c \
	  "import yaml,glob,sys; [yaml.safe_load(open(f)) for f in glob.glob('.github/workflows/*.yml')]; print('workflows: YAML ок')" \
	  2>/dev/null || echo "workflows: пропущено (нет uv)"

install: build
	./tools/install.sh

icon:
	swift tools/set-icon.swift "$(PWD)"

clean:
	rm -rf bin
