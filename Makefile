APP_NAME := nimbus
VERSION := 0.1.0
BUILD_DIR := build
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: all build build-all clean test lint install uninstall

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
	@if [ "$$(uname -s 2>/dev/null)" = "Linux" ] || [ "$$(uname -s 2>/dev/null)" = "Darwin" ]; then \
		echo "Installing to /usr/local/bin/$(APP_NAME)..."; \
		sudo cp $(BUILD_DIR)/$(APP_NAME) /usr/local/bin/$(APP_NAME); \
		sudo chmod +x /usr/local/bin/$(APP_NAME); \
		echo "Done. Run 'nimbus' from anywhere."; \
	elif [ -n "$$USERPROFILE" ]; then \
		INSTALL_DIR="$$USERPROFILE/.nimbus/bin"; \
		mkdir -p "$$INSTALL_DIR"; \
		cp $(BUILD_DIR)/$(APP_NAME) "$$INSTALL_DIR/$(APP_NAME).exe"; \
		powershell -Command "\
			$$current = [Environment]::GetEnvironmentVariable('Path', 'User'); \
			if ($$current -notlike '*$$env:USERPROFILE\\.nimbus\\bin*') { \
				[Environment]::SetEnvironmentVariable('Path', $$current + ';' + '$$env:USERPROFILE\\.nimbus\\bin', 'User'); \
				Write-Host 'Added to PATH. Restart your terminal to use nimbus from anywhere.'; \
			} else { \
				Write-Host 'Already in PATH.'; \
			}"; \
		echo "Installed to $$INSTALL_DIR/$(APP_NAME).exe"; \
	else \
		echo "Unknown platform. Copy $(BUILD_DIR)/$(APP_NAME) to a directory in your PATH."; \
	fi

uninstall:
	@if [ "$$(uname -s 2>/dev/null)" = "Linux" ] || [ "$$(uname -s 2>/dev/null)" = "Darwin" ]; then \
		sudo rm -f /usr/local/bin/$(APP_NAME); \
		echo "Removed /usr/local/bin/$(APP_NAME)"; \
	elif [ -n "$$USERPROFILE" ]; then \
		rm -f "$$USERPROFILE/.nimbus/bin/$(APP_NAME).exe"; \
		echo "Removed $$USERPROFILE/.nimbus/bin/$(APP_NAME).exe"; \
	fi

clean:
	rm -rf $(BUILD_DIR) nimbus nimbus.exe
