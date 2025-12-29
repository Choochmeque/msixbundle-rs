# msixbundle

Rust library for building and signing Windows MSIX packages and bundles using the Windows SDK toolchain.

## Installation

```toml
[dependencies]
msixbundle = "1.0"
```

## Features

- **SDK auto-discovery**: Automatically locate Windows SDK tools via registry
- **Manifest parsing**: Extract version and display name from `AppxManifest.xml`
- **Package creation**: Create `.msix` files for each architecture
- **Bundle creation**: Combine multiple `.msix` files into a `.msixbundle`
- **Code signing**: Sign packages and bundles with PFX certificates
- **Timestamping**: Support for RFC3161 and Authenticode protocols
- **Validation**: Validate packages using WACK and verify signatures

## API

| Function | Description |
|----------|-------------|
| `locate_sdk_tools()` | Find Windows SDK tools on the system |
| `read_manifest_info()` | Parse AppxManifest.xml for version and identity |
| `pack_arch()` | Create a per-architecture .msix package |
| `build_bundle()` | Combine multiple .msix files into a .msixbundle |
| `sign_artifact()` | Sign packages/bundles with a PFX certificate |
| `verify_signature()` | Verify digital signatures |
| `validate_package()` | Validate packages using WACK |

## Usage

```rust
use msixbundle::*;
use std::path::Path;

fn main() -> anyhow::Result<()> {
    // Locate Windows SDK tools
    let tools = locate_sdk_tools()?;

    // Read manifest information
    let x64_dir = Path::new("./build/x64/AppxContent");
    let manifest = read_manifest_info(x64_dir)?;
    println!("Building {} v{}", manifest.display_name, manifest.version);

    // Pack architectures
    let out_dir = Path::new("./output");
    let x64_msix = pack_arch(&tools, x64_dir, out_dir, &manifest, "x64")?;

    let arm64_dir = Path::new("./build/arm64/AppxContent");
    let arm64_msix = pack_arch(&tools, arm64_dir, out_dir, &manifest, "arm64")?;

    // Build bundle
    let packages = vec![
        ("x64".to_string(), x64_msix),
        ("arm64".to_string(), arm64_msix),
    ];
    let bundle = build_bundle(&tools, out_dir, &packages, &manifest)?;

    // Sign the bundle
    let pfx = Path::new("./signing.pfx");
    sign_artifact(&tools, &SignOptions {
        artifact: &bundle,
        pfx,
        password: Some("password"),
        sip_dll: None,
        timestamp_url: Some("http://timestamp.digicert.com"),
        rfc3161: true,
        signtool_override: None,
    })?;

    // Verify the signature
    verify_signature(&tools, &bundle)?;

    println!("Bundle created: {}", bundle.display());
    Ok(())
}
```

## Cargo Features

### `sdk-discovery` (default)

Automatically locates Windows SDK tools via the Windows registry.

```toml
[dependencies]
msixbundle = { version = "1.0", default-features = true }
```

To disable auto-discovery and provide paths manually:

```toml
[dependencies]
msixbundle = { version = "1.0", default-features = false }
```

## Error Handling

The library uses `anyhow::Result` for error handling and provides custom error types via `MsixError`:

- `ToolMissing`: Windows SDK tool not found
- `MakeAppx`: MakeAppx.exe operation failed
- `SignTool`: signtool.exe operation failed
- `Manifest`: Manifest parsing error
- `Validation`: WACK validation failed

## Requirements

- Windows OS with Windows SDK 10 installed
- MakeAppx.exe, signtool.exe, and appcert.exe (for validation)

## License

MIT License
