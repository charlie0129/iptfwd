MAKEFLAGS += --no-print-directory --always-make --silent

TARGET = iptfwd

all: bin/$(TARGET)

bin:
	mkdir -p bin

bin/$(TARGET): bin
	go build -ldflags "-s -w" -gcflags="all=-trimpath=$$(pwd)" -asmflags="all=-trimpath=$$(pwd)" -o bin/$(TARGET) main.go
