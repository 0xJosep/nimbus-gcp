#!/usr/bin/env bash
set -e

APP_NAME="nimbus"

echo "Building $APP_NAME..."
CGO_ENABLED=0 go build -ldflags "-s -w" -o "build/$APP_NAME" ./cmd/nimbus/

OS="$(uname -s)"
case "$OS" in
    Linux|Darwin)
        echo "Installing to /usr/local/bin/$APP_NAME..."
        sudo cp "build/$APP_NAME" "/usr/local/bin/$APP_NAME"
        sudo chmod +x "/usr/local/bin/$APP_NAME"
        echo "Done. Run 'nimbus' from anywhere."
        ;;
    MINGW*|MSYS*|CYGWIN*|Windows_NT)
        INSTALL_DIR="$USERPROFILE/.nimbus/bin"
        mkdir -p "$INSTALL_DIR"
        cp "build/$APP_NAME" "$INSTALL_DIR/$APP_NAME.exe"

        powershell -Command "
            \$current = [Environment]::GetEnvironmentVariable('Path', 'User');
            \$nimbusPath = \"\$env:USERPROFILE\.nimbus\bin\";
            if (\$current -notlike \"*\$nimbusPath*\") {
                [Environment]::SetEnvironmentVariable('Path', \$current + ';' + \$nimbusPath, 'User');
                Write-Host 'Added to PATH. Restart your terminal to use nimbus from anywhere.';
            } else {
                Write-Host 'Already in PATH.';
            }"
        echo "Installed to $INSTALL_DIR/$APP_NAME.exe"
        ;;
    *)
        echo "Unknown OS: $OS"
        echo "Copy build/$APP_NAME to a directory in your PATH."
        ;;
esac
