# Build script for KPM CorePatch
# This script helps build the module for different architectures

#!/bin/bash

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

echo_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

echo_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

show_help() {
    cat << EOF
KPM CorePatch Build Script

Usage: $0 [OPTIONS]

Options:
    -a, --arch ARCH      Target architecture (arm64, arm, x86_64, x86)
                         Default: auto-detect or arm64
    -d, --debug          Enable debug build with verbose logging
    -c, --clean          Clean build artifacts before building
    -h, --help           Show this help message

Examples:
    $0                    # Build for default architecture
    $0 -a arm64           # Build for ARM64
    $0 -a arm -d          # Build for ARM with debug enabled
    $0 -c                 # Clean and build

Supported Architectures:
    arm64    - AArch64 (most modern Android devices)
    arm      - ARM 32-bit (older Android devices)
    x86_64   - x86 64-bit (emulators, some tablets)
    x86      - x86 32-bit (older emulators)

Prerequisites:
    - GCC cross-compiler for target architecture
    - Make build system
    - KPM SDK (for KernelSU/Apatch)

EOF
}

# Default values
ARCH=""
DEBUG=""
CLEAN=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -a|--arch)
            ARCH="$2"
            shift 2
            ;;
        -d|--debug)
            DEBUG="1"
            shift
            ;;
        -c|--clean)
            CLEAN=true
            shift
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            echo_error "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

# Auto-detect architecture if not specified
if [ -z "$ARCH" ]; then
    DETECTED_ARCH=$(uname -m)
    case $DETECTED_ARCH in
        aarch64|arm64)
            ARCH="arm64"
            ;;
        armv7l|armhf|arm)
            ARCH="arm"
            ;;
        x86_64)
            ARCH="x86_64"
            ;;
        i686|i386)
            ARCH="x86"
            ;;
        *)
            echo_warn "Could not auto-detect architecture, defaulting to arm64"
            ARCH="arm64"
            ;;
    esac
    echo_info "Auto-detected architecture: $ARCH"
fi

# Validate architecture
case $ARCH in
    arm64|arm|x86_64|x86)
        echo_info "Building for architecture: $ARCH"
        ;;
    *)
        echo_error "Unsupported architecture: $ARCH"
        echo "Supported: arm64, arm, x86_64, x86"
        exit 1
        ;;
esac

# Check for required tools
check_tool() {
    local tool=$1
    local package=$2
    
    if ! command -v "$tool" &> /dev/null; then
        echo_error "'$tool' not found"
        if [ -n "$package" ]; then
            echo "Install it with: sudo apt install $package"
        fi
        exit 1
    fi
}

echo_info "Checking build dependencies..."
check_tool "make" "make"
check_tool "gcc" "gcc"

# Set up cross-compiler based on architecture
setup_cross_compiler() {
    case $ARCH in
        arm64)
            export CROSS_COMPILE="aarch64-linux-gnu-"
            check_tool "aarch64-linux-gnu-gcc" "gcc-aarch64-linux-gnu"
            ;;
        arm)
            export CROSS_COMPILE="arm-linux-gnueabi-"
            check_tool "arm-linux-gnueabi-gcc" "gcc-arm-linux-gnueabi"
            ;;
        x86_64)
            export CROSS_COMPILE="x86_64-linux-gnu-"
            check_tool "x86_64-linux-gnu-gcc" "gcc-x86-64-linux-gnu"
            ;;
        x86)
            export CROSS_COMPILE="i686-linux-gnu-"
            check_tool "i686-linux-gnu-gcc" "gcc-i686-linux-gnu"
            ;;
    esac
}

# Clean if requested
if [ "$CLEAN" = true ]; then
    echo_info "Cleaning build artifacts..."
    make clean
fi

# Setup cross-compiler
setup_cross_compiler

# Build
echo_info "Building KPM CorePatch..."
if [ -n "$DEBUG" ]; then
    make ARCH="$ARCH" DEBUG=1
else
    make ARCH="$ARCH"
fi

# Check output
OUTPUT_FILE="corepatch.kpm"
if [ -f "$OUTPUT_FILE" ]; then
    echo_info "Build successful!"
    echo_info "Output file: $(pwd)/$OUTPUT_FILE"
    ls -lh "$OUTPUT_FILE"
else
    echo_error "Build failed - output file not found"
    exit 1
fi

echo ""
echo_info "To install on your device:"
echo "  1. Copy $OUTPUT_FILE to your device"
echo "  2. Place it in /data/adb/modules/"
echo "  3. Reboot your device"
echo ""
echo_info "Or use: make install (requires root access)"
