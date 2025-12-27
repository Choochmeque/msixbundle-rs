# msixbundle-rs

A Rust library and CLI tool for building and signing Windows MSIX packages and MSIX bundles using the Windows SDK toolchain (MakeAppx and SignTool).

## Overview

`msixbundle-rs` provides a programmatic Rust interface to automate the creation, signing, and validation of multi-architecture MSIX packages and bundles. It's designed for build pipelines that need to package Windows applications for distribution via the Microsoft Store or enterprise deployment.

## Features

- **Multi-architecture support**: Build separate MSIX packages for x64 and ARM64 architectures
- **Automatic bundle creation**: Combine per-architecture packages into a single `.msixbundle`
- **SDK auto-discovery**: Automatically locate Windows SDK tools (`MakeAppx.exe`, `signtool.exe`, `appcert.exe`) via registry
- **Code signing**: Sign packages and bundles with PFX certificates
- **Timestamping**: Support for both RFC3161 and Authenticode timestamp protocols
- **Validation**: Validate packages using Windows App Certification Kit (WACK) and verify signatures
- **Manifest parsing**: Extract version and display name from `AppxManifest.xml`
- **Library and CLI**: Use as a Rust library or standalone command-line tool

## Components

### Library: `msixbundle`

The core library providing the building blocks for MSIX packaging operations.

**Key APIs:**
- `locate_sdk_tools()` - Find Windows SDK tools on the system
- `read_manifest_info()` - Parse AppxManifest.xml for version and identity
- `pack_arch()` - Create a per-architecture .msix package
- `build_bundle()` - Combine multiple .msix files into a .msixbundle
- `sign_artifact()` - Sign packages/bundles with a PFX certificate
- `verify_signature()` - Verify digital signatures
- `validate_package()` - Validate packages using WACK (Windows App Certification Kit)

### CLI: `msixbundle-cli`

Command-line interface for packaging workflows.

## Installation

### As a CLI tool

```bash
cargo install --path msixbundle-cli
```

### As a library

Add to your `Cargo.toml`:

```toml
[dependencies]
msixbundle = "0.1.0"
```

## Usage

### CLI Tool

Basic usage - build a bundle from x64 and ARM64 app directories:

```bash
msixbundle-cli \
  --out-dir ./output \
  --dir-x64 ./build/x64/AppxContent \
  --dir-arm64 ./build/arm64/AppxContent
```

Build and sign with a PFX certificate:

```bash
msixbundle-cli \
  --out-dir ./output \
  --dir-x64 ./build/x64/AppxContent \
  --dir-arm64 ./build/arm64/AppxContent \
  --pfx ./certificates/signing.pfx \
  --pfx-password "YourPassword" \
  --timestamp-url http://timestamp.digicert.com \
  --timestamp-mode rfc3161
```

Sign individual architecture packages before bundling:

```bash
msixbundle-cli \
  --out-dir ./output \
  --dir-x64 ./build/x64/AppxContent \
  --dir-arm64 ./build/arm64/AppxContent \
  --sign-each \
  --pfx ./signing.pfx \
  --pfx-password "secret"
```

With validation and verification:

```bash
msixbundle-cli \
  --out-dir ./output \
  --dir-x64 ./build/x64/AppxContent \
  --pfx ./signing.pfx \
  --pfx-password "secret" \
  --validate \
  --verify \
  --verbose
```

#### CLI Options

| Option | Description |
|--------|-------------|
| `--out-dir` | Output directory for generated .msix and .msixbundle files |
| `--dir-x64` | Path to x64 AppxContent directory containing AppxManifest.xml |
| `--dir-arm64` | Path to ARM64 AppxContent directory |
| `--pfx` | Path to PFX certificate file for signing |
| `--pfx-password` | Password for the PFX certificate |
| `--sign-each` | Sign individual architecture packages (not just the bundle) |
| `--signtool-path` | Override path to signtool.exe |
| `--sip-dll` | Path to Appx SIP DLL (e.g., `C:\Windows\System32\AppxSip.dll`) |
| `--timestamp-url` | Timestamp server URL (default: `http://timestamp.digicert.com`) |
| `--timestamp-mode` | Timestamping protocol: `rfc3161` or `authenticode` (default: `rfc3161`) |
| `--validate` | Validate packages using WACK (Windows App Certification Kit) |
| `--verify` | Verify signatures with SignTool after signing |
| `--verbose` | Enable verbose logging (sets `RUST_LOG=info`) |

### Library API

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

## Requirements

- **Windows OS**: This tool requires Windows and the Windows SDK
- **Windows SDK 10**: MakeAppx.exe and signtool.exe must be installed
  - Install via [Visual Studio](https://visualstudio.microsoft.com/) or [standalone SDK](https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/)
- **Windows App Certification Kit (WACK)**: Required for `--validate` flag (appcert.exe)
  - Installed automatically with the Windows SDK
  - Note: WACK validation may require administrator privileges on some systems
- **Rust**: 1.70+ (2021 edition)

The library can automatically discover SDK tools via the Windows registry, or you can provide explicit paths.

## How It Works

1. **Manifest Parsing**: Reads `AppxManifest.xml` from each architecture directory to extract version and identity information
2. **Package Creation**: Uses `MakeAppx.exe` to create `.msix` files for each architecture from the AppxContent directories
3. **Bundle Mapping**: Generates a `bundlemap.txt` file listing all architecture packages
4. **Bundle Creation**: Uses `MakeAppx.exe` to combine packages into a `.msixbundle`
5. **Signing**: Uses `signtool.exe` to apply digital signatures with optional timestamping
6. **Validation**: Optionally validates packages with WACK and verifies signature validity

## Creating a Self-Signed Certificate for Testing

For development and testing, you can create a self-signed certificate. **Note: Self-signed certificates are only for local testing. Microsoft Store submissions do not require pre-signing as the Store handles signing automatically.**

### Important: Certificate Subject Must Match Manifest Publisher

The certificate's Common Name (CN) **must exactly match** the Publisher attribute in your `AppxManifest.xml`:

```xml
<Identity Name="YourApp" Publisher="CN=YourCompany" Version="1.0.0.0" />
```

If your manifest has `Publisher="CN=YourCompany"`, your certificate must also have `CN=YourCompany`.

### Using PowerShell (Recommended on Windows)

```powershell
# Replace "CN=YourCompany" with the Publisher value from your AppxManifest.xml
$cert = New-SelfSignedCertificate -Type Custom -Subject "CN=YourCompany" `
    -KeyUsage DigitalSignature -FriendlyName "MSIX Test Certificate" `
    -CertStoreLocation "Cert:\CurrentUser\My" `
    -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.3", "2.5.29.19={text}")

# Export to PFX file
$password = ConvertTo-SecureString -String "YourPassword" -Force -AsPlainText
Export-PfxCertificate -Cert $cert -FilePath ".\test-certificate.pfx" -Password $password

# Install to Trusted Root (required for local testing/installation)
$store = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "LocalMachine")
$store.Open("ReadWrite")
$store.Add($cert)
$store.Close()
```

### Using OpenSSL

```bash
# Replace "CN=YourCompany" with the Publisher value from your AppxManifest.xml
# Generate a private key
openssl genrsa -out private.key 2048

# Create a certificate signing request
openssl req -new -key private.key -out request.csr -subj "/CN=YourCompany"

# Generate a self-signed certificate
openssl x509 -req -days 365 -in request.csr -signkey private.key -out certificate.crt

# Export to PFX format
openssl pkcs12 -export -out test-certificate.pfx -inkey private.key -in certificate.crt -password pass:YourPassword
```

### Installing the Certificate for Testing

To install MSIX packages signed with a self-signed certificate on your local machine, the certificate must be in the Trusted Root Certification Authorities store:

**Using PowerShell (as Administrator):**
```powershell
Import-PfxCertificate -FilePath ".\test-certificate.pfx" -CertStoreLocation Cert:\LocalMachine\Root -Password (ConvertTo-SecureString -String "YourPassword" -Force -AsPlainText)
```

**Using Certificate Manager (certmgr.msc):**
1. Run `certmgr.msc` as Administrator
2. Right-click **Trusted Root Certification Authorities** → **All Tasks** → **Import**
3. Select your `.pfx` file and complete the wizard

### Important Notes

- **Microsoft Store**: No certificate needed - submit unsigned packages, the Store signs them
- **Enterprise/Sideloading**: Use a certificate from a trusted Certificate Authority
- **Local Testing**: Self-signed certificates work after installing to Trusted Root
- Self-signed certificates will cause security warnings on other machines unless installed there too
- Remove test certificates from Trusted Root after testing for security

### Using with msixbundle-cli

Once you have a PFX certificate with matching CN, use it with the tool:

```bash
msixbundle-cli \
  --out-dir ./output \
  --dir-x64 ./build/x64/AppxContent \
  --pfx ./test-certificate.pfx \
  --pfx-password "YourPassword"
```

## Project Structure

```
msixbundle-rs/
├── msixbundle/          # Core library
│   ├── src/
│   │   └── lib.rs       # Main library implementation
│   └── Cargo.toml
├── msixbundle-cli/      # Command-line tool
│   ├── src/
│   │   └── main.rs      # CLI implementation
│   └── Cargo.toml
└── Cargo.toml           # Workspace configuration
```

## Error Handling

The library uses `anyhow::Result` for error handling and provides custom error types via `MsixError`:

- `ToolMissing`: Windows SDK tool not found
- `MakeAppx`: MakeAppx.exe operation failed
- `SignTool`: signtool.exe operation failed
- `Manifest`: Manifest parsing error
- `Validation`: WACK validation failed

## Features

### SDK Discovery

Enabled by default. Automatically locates Windows SDK tools via registry.

```toml
[dependencies]
msixbundle = { version = "0.1.0", default-features = true }
```

To disable auto-discovery and provide paths manually:

```toml
[dependencies]
msixbundle = { version = "0.1.0", default-features = false }
```

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

## License

MIT License - see the LICENSE file for details.

## Resources

- [MSIX Documentation](https://docs.microsoft.com/en-us/windows/msix/)
- [MakeAppx.exe Tool Reference](https://docs.microsoft.com/en-us/windows/msix/package/create-app-package-with-makeappx-tool)
- [SignTool.exe Documentation](https://docs.microsoft.com/en-us/windows/win32/seccrypto/signtool)
- [AppxManifest Schema](https://docs.microsoft.com/en-us/uwp/schemas/appxpackage/uapmanifestschema/schema-root)

## See Also

- [Windows App SDK](https://docs.microsoft.com/en-us/windows/apps/windows-app-sdk/)
- [Partner Center App Submission](https://docs.microsoft.com/en-us/windows/uwp/publish/)
