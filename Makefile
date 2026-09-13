BINARY_PATH ?= ./bin/manip.exe
MAIN_PATH := ./cmd/manip/

.DEFAULT_GOAL := help

.PHONY: build clean help

build:
	go build -o $(BINARY_PATH) $(MAIN_PATH)

clean:
	@echo "Cleaning up..."
	@rm -f $(BINARY_PATH)
	@go clean
	@echo "Done!"

help:
	@echo "Commands:"
	@echo "  make build - Builds the CLI into a binary"
	@echo "  make clean - Removes the built CLI binary"