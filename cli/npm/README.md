# Toob CLI

> Hardware Package Manager for the Toob-Boot embedded IoT ecosystem.

Toob manages chip HAL packages, registry synchronization, and orchestrates the full build pipeline for Toob-Boot firmware on RISC-V and ARM microcontrollers.

## Installation

```bash
npm install -g toob
```

Or run directly without installing:

```bash
npx toob init my-firmware
```

## Quick Start

```bash
# Create a new firmware project
toob init my-firmware
cd my-firmware

# Browse and add a chip
toob chip list
toob chip add esp32c6

# Build the firmware
toob build
```

## Commands

| Command                  | Description                                          |
| ------------------------ | ---------------------------------------------------- |
| `toob init [name]`       | Initialize a new Toob-Boot IoT project               |
| `toob build`             | Run the full build pipeline (manifest → cmake → ninja)|
| `toob chip list [query]` | List all chips available in the registry              |
| `toob chip add [name]`   | Install a chip HAL from the registry                  |
| `toob chip info [name]`  | Show detailed information about a chip                |
| `toob chip remove [name]`| Uninstall a chip HAL                                  |
| `toob install`           | Install all toolchains from toob.lock                 |
| `toob doctor`            | Check system environment and dependencies             |
| `toob clean`             | Remove all build artifacts                            |
| `toob update`            | Self-update to the latest version                     |

## How It Works

This npm package is a lightweight wrapper (~5KB) around the native Toob CLI binary. During installation, the correct pre-built binary for your platform is automatically downloaded from [GitHub Releases](https://github.com/Toob-Boot/Toob-CLI-Release/releases).

Supported platforms:
- **Windows** x64
- **macOS** x64, ARM64 (Apple Silicon)
- **Linux** x64

After the initial install, `toob update` will update the binary in-place — no `npm update` needed.

## Links

- [Documentation](https://github.com/Toob-Boot/Toob-Loader)
- [Registry](https://github.com/Toob-Boot/Toob-Registry)
- [Releases](https://github.com/Toob-Boot/Toob-CLI-Release/releases)

## License

MIT
