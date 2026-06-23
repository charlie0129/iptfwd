MAKEFLAGS += --no-print-directory --always-make --silent

BIN    ?= iptfwd
PREFIX ?= /usr/local/bin

all: bin/$(BIN)

bin:
	mkdir -p bin

bin/$(BIN): bin
	CGO_ENABLED=0 GOOS=linux go build -ldflags "-s -w" -gcflags="all=-trimpath=$$(pwd)" -asmflags="all=-trimpath=$$(pwd)" -o bin/$(BIN) main.go

install: bin/$(BIN)
	install bin/$(BIN) $(PREFIX)
