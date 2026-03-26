APP_NAME := nimbus
VERSION := 0.1.0
BUILD_DIR := build
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: all build build-all clean test lint install

all: build

build:
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(APP_NAME) ./cmd/nimbus/

# Cross-compile for all major platforms.
# Pure-Go SQLite (modernc.org/sqlite) — no CGO, no C compiler needed.
build-all: build-linux-amd64 build-linux-arm64 build-darwin-amd64 build-darwin-arm64 build-windows-amd64

build-linux-amd64:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
		go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(APP_NAME)-linux-amd64 ./cmd/nimbus/

build-linux-arm64:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
		go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(APP_NAME)-linux-arm64 ./cmd/nimbus/

build-darwin-amd64:
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 \
		go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(APP_NAME)-darwin-amd64 ./cmd/nimbus/

build-darwin-arm64:
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 \
		go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(APP_NAME)-darwin-arm64 ./cmd/nimbus/

build-windows-amd64:
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 \
		go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(APP_NAME)-windows-amd64.exe ./cmd/nimbus/

test:
	go test ./...

lint:
	go vet ./...

install: build
	cp $(BUILD_DIR)/$(APP_NAME) $(GOPATH)/bin/$(APP_NAME)

clean:
	rm -rf $(BUILD_DIR) nimbus nimbus.exe
