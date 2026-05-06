# KPM CorePatch - KernelSU/Apatch Module

KPM (Kernel Patch Module) implementation of CorePatch functionality for KernelSU and Apatch.
This module disables Android signature verification at the kernel level, allowing:
- App downgrades
- Installation of modified APKs
- Installation with inconsistent signatures

## Features

- **Downgrade apps**: Install older versions of apps
- **Install modified APKs**: Bypass digest/signature verification
- **Install with inconsistent signatures**: Override signature mismatch errors
- **Shared UID support**: Handle shared user ID scenarios
- **Verification bypass**: Disable package verification agent

## Supported Android Versions

Based on the original CorePatch Xposed module, this KPM supports:
- Android 10 (API 29)
- Android 11 (API 30)
- Android 12/12L (API 31/32)
- Android 13 (API 33)
- Android 14 (API 34)
- Android 15 (API 35)
- Android 16 (API 36)

## Requirements

- KernelSU or Apatch installed
- Compatible kernel with KPM support
- Root access

## Installation

1. Download the latest `corepatch.kpm` release
2. Open KernelSU/Apatch manager app
3. Navigate to the Superuser or Modules section
4. Flash/install the KPM file
5. Reboot your device

## Configuration

The module can be configured through the following options (set via KPM interface):

- `downgrade`: Allow app downgrades (default: true)
- `authcreak`: Break authentication/digest checks (default: false)
- `digestCreak`: Break digest verification (default: true)
- `exactSigCheck`: Allow exact signature check bypass (default: false)
- `UsePreSig`: Use previous signature for verification (default: false)
- `bypassBlock`: Bypass installation blocks (default: true)
- `sharedUser`: Enable shared UID support (default: false)
- `disableVerificationAgent`: Disable verification agent (default: true)

## Building

### Prerequisites

- Linux/macOS environment
- GCC or Clang compiler
- Kernel headers for your device
- KPM SDK from KernelSU/Apatch

### Build Instructions

```bash
# Clone the repository
git clone https://github.com/yourusername/kpm_corepatch.git
cd kpm_corepatch

# Set up cross-compilation toolchain (example for ARM64)
export CROSS_COMPILE=aarch64-linux-gnu-
export ARCH=arm64

# Build the module
make

# Output: corepatch.kpm
```

### Using the build script

```bash
# Build for arm64
./build.sh -a arm64

# Build for all architectures
./build.sh -a all

# Clean build directory
./build.sh -c
```

### GitHub Actions CI/CD

This project includes automated builds via GitHub Actions. Every push to the `main` branch
or pull request will trigger builds for all supported architectures (arm64, arm, x86_64).

Built artifacts are automatically uploaded as workflow artifacts and can be downloaded
from the GitHub Actions tab. For main branch pushes, a combined release archive is created
with all architecture variants.

To manually trigger a build, go to the Actions tab and run the "Build KPM CorePatch" workflow.

## Usage

Once installed, the module automatically hooks into the Android PackageManagerService
and applies patches to bypass signature verification during app installation.

No additional configuration is typically needed - the module works out of the box
with sensible defaults.

## Troubleshooting

### Module not loading
- Ensure KernelSU/Apatch is properly installed
- Check that your kernel supports KPM
- Verify the KPM file is not corrupted

### Apps still failing to install
- Try enabling `authcreak` option
- Check logcat for error messages
- Ensure you're using a compatible Android version

## Credits

- Original CorePatch by coderstory/LSPosed
- KernelSU Project
- Apatch Project
- KPM SDK contributors

## License

GPL v2 License - See LICENSE file for details

## Support

- Report issues on GitHub
- Join community discussions on Telegram
