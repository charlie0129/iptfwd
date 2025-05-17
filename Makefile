MAKEFLAGS += --no-print-directory --always-make --silent

TARGET := iptfwd
PREFIX ?= /usr/local/bin

all: bin/$(TARGET)

bin:
	mkdir -p bin

bin/$(TARGET): bin
	GOOS=linux go build -ldflags "-s -w" -gcflags="all=-trimpath=$$(pwd)" -asmflags="all=-trimpath=$$(pwd)" -o bin/$(TARGET) main.go

install: bin/$(TARGET)
	install bin/$(TARGET) $(PREFIX)
