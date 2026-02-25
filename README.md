# msixbundle-rs

A Rust library and CLI tool for building and signing Windows MSIX packages and MSIX bundles using the Windows SDK toolchain.

## Overview

`msixbundle-rs` provides a programmatic Rust interface to automate the creation, signing, and validation of multi-architecture MSIX packages and bundles. It's designed for build pipelines that need to package Windows applications for distribution via the Microsoft Store or enterprise deployment.

## Crates

| Crate | Description | crates.io |
|-------|-------------|-----------|
| [msixbundle](./msixbundle) | Core library for MSIX packaging operations | [![crates.io](https://img.shields.io/crates/v/msixbundle.svg)](https://crates.io/crates/msixbundle) |
| [msixbundle-cli](./msixbundle-cli) | Command-line tool for packaging workflows | [![crates.io](https://img.shields.io/crates/v/msixbundle-cli.svg)](https://crates.io/crates/msixbundle-cli) |

## Features

- **Multi-architecture support**: Build separate MSIX packages for x64 and ARM64 architectures
- **Automatic bundle creation**: Combine per-architecture packages into a single `.msixbundle`
- **SDK auto-discovery**: Automatically locate Windows SDK tools (`MakeAppx.exe`, `makepri.exe`, `signtool.exe`, `appcert.exe`) via registry
- **Resource indexing**: Optionally generate `resources.pri` with `makepri.exe` for qualified assets
- **Code signing**: Sign packages and bundles with PFX certificates
- **Timestamping**: Support for both RFC3161 and Authenticode timestamp protocols
- **Validation**: Validate packages using Windows App Certification Kit (WACK) and verify signatures
- **Manifest parsing**: Extract version and display name from `AppxManifest.xml`

## Requirements

- **Windows OS**: This tool requires Windows and the Windows SDK
- **Windows SDK 10**: MakeAppx.exe, MakePri.exe and signtool.exe must be installed
  - Install via [Visual Studio](https://visualstudio.microsoft.com/) or [standalone SDK](https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/)
- **Windows App Certification Kit (WACK)**: Required for validation (appcert.exe)
  - Installed automatically with the Windows SDK
- **Rust**: 1.70+ (2021 edition)

## Quick Start

### CLI Tool

```bash
cargo install msixbundle-cli
```

```bash
msixbundle-cli \
  --out-dir ./output \
  --dir-x64 ./build/x64/AppxContent \
  --dir-arm64 ./build/arm64/AppxContent \
  --pfx ./signing.pfx \
  --pfx-password "secret"
```

### Library

```toml
[dependencies]
msixbundle = "1.1"
```

```rust
use msixbundle::*;

let tools = locate_sdk_tools()?;
let manifest = read_manifest_info(x64_dir)?;
let msix = pack_arch(&tools, x64_dir, out_dir, &manifest, "x64")?;
```

See the individual crate READMEs for detailed documentation.

## Project Structure

```
msixbundle-rs/
├── msixbundle/          # Core library
│   ├── src/
│   │   └── lib.rs
│   └── Cargo.toml
├── msixbundle-cli/      # Command-line tool
│   ├── src/
│   │   └── main.rs
│   └── Cargo.toml
└── Cargo.toml           # Workspace configuration
```

## How It Works

1. **Manifest Parsing**: Reads `AppxManifest.xml` from each architecture directory to extract version and identity information
2. **Resource Indexing (optional)**: Uses `makepri.exe` to generate `resources.pri`
3. **Package Creation**: Uses `MakeAppx.exe` to create `.msix` files for each architecture
4. **Bundle Mapping**: Generates a `bundlemap.txt` file listing all architecture packages
5. **Bundle Creation**: Uses `MakeAppx.exe` to combine packages into a `.msixbundle`
6. **Signing**: Uses `signtool.exe` to apply digital signatures with optional timestamping
7. **Validation**: Optionally validates packages with WACK and verifies signature validity

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

## License

MIT License - see the [LICENSE](LICENSE) file for details.

## Resources

- [MSIX Documentation](https://docs.microsoft.com/en-us/windows/msix/)
- [MakeAppx.exe Tool Reference](https://docs.microsoft.com/en-us/windows/msix/package/create-app-package-with-makeappx-tool)
- [SignTool.exe Documentation](https://docs.microsoft.com/en-us/windows/win32/seccrypto/signtool)
- [MakePri.exe Tool Reference](https://learn.microsoft.com/en-us/windows/uwp/app-resources/compile-resources-manually-with-makepri)
- [Windows App Certification Kit (WACK)](https://docs.microsoft.com/en-us/windows/uwp/debug-test-perf/windows-app-certification-kit)
- [AppxManifest Schema](https://docs.microsoft.com/en-us/uwp/schemas/appxpackage/uapmanifestschema/schema-root)
