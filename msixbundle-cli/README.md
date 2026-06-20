# msixbundle-cli

Command-line tool for building and signing Windows MSIX packages and bundles.

## Installation

```bash
cargo install msixbundle-cli
```

## Usage

### Basic Usage

Build a bundle from x64 and ARM64 app directories:

```bash
msixbundle-cli \
  --out-dir ./output \
  --dir-x64 ./build/x64/AppxContent \
  --dir-arm64 ./build/arm64/AppxContent
```

### Build and Sign with PFX

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

### Build and Sign with Certificate Thumbprint

Sign using a certificate from the Windows certificate store:

```bash
msixbundle-cli \
  --out-dir ./output \
  --dir-x64 ./build/x64/AppxContent \
  --dir-arm64 ./build/arm64/AppxContent \
  --thumbprint "1a2b3c4d5e6f..." \
  --cert-store My \
  --timestamp-url http://timestamp.digicert.com
```

For certificates in the machine store:

```bash
msixbundle-cli \
  --out-dir ./output \
  --dir-x64 ./build/x64/AppxContent \
  --thumbprint "1a2b3c4d5e6f..." \
  --machine-store
```

### Sign Individual Packages

Sign each architecture package before bundling:

```bash
msixbundle-cli \
  --out-dir ./output \
  --dir-x64 ./build/x64/AppxContent \
  --dir-arm64 ./build/arm64/AppxContent \
  --sign-each \
  --pfx ./signing.pfx \
  --pfx-password "secret"
```

### Generate resources.pri with MakePri

Generate `resources.pri` before packing (useful for scale-qualified assets such as `SquareLogo.scale-200.png`):

```bash
msixbundle-cli \
  --out-dir ./output \
  --dir-x64 ./build/x64/AppxContent \
  --makepri \
  --makepri-default-language en-us \
  --makepri-target-os-version 10.0.0
```

### With Validation and Verification

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

## Options

| Option | Description |
|--------|-------------|
| `--out-dir` | Output directory for generated .msix and .msixbundle files |
| `--dir-x64` | Path to x64 AppxContent directory containing AppxManifest.xml |
| `--dir-arm64` | Path to ARM64 AppxContent directory |
| `--pfx` | Path to PFX certificate file for signing (mutually exclusive with `--thumbprint`) |
| `--pfx-password` | Password for the PFX certificate |
| `--thumbprint` | Certificate thumbprint (SHA1) from Windows cert store (mutually exclusive with `--pfx`) |
| `--cert-store` | Certificate store name (default: `My`). Common: "My" (Personal), "Root", "CA". See [SignTool docs](https://learn.microsoft.com/en-us/dotnet/framework/tools/signtool-exe) |
| `--machine-store` | Use machine certificate store instead of user store |
| `--sign-each` | Sign individual architecture packages (not just the bundle) |
| `--signtool-path` | Override path to signtool.exe |
| `--sip-dll` | Path to Appx SIP DLL (e.g., `C:\Windows\System32\AppxSip.dll`) |
| `--timestamp-url` | Timestamp server URL (default: `http://timestamp.digicert.com`) |
| `--timestamp-mode` | Timestamping protocol: `rfc3161` or `authenticode` (default: `rfc3161`) |
| `--makepri` | Generate `resources.pri` with MakePri before packing |
| `--makepri-path` | Override path to `makepri.exe` |
| `--makepri-default-language` | Default language qualifier for MakePri (example: `en-us`) |
| `--makepri-target-os-version` | MakePri `/pv` target OS version (example: `10.0.0`) |
| `--makepri-keep-config` | Keep generated `priconfig.xml` files |
| `--validate` | Validate packages using WACK (Windows App Certification Kit) |
| `--verify` | Verify signatures with SignTool after signing |
| `--verbose` | Enable verbose logging (sets `RUST_LOG=info`) |
| `--force` | Overwrite existing output files |

## Creating a Self-Signed Certificate

For development and testing, create a self-signed certificate. The certificate's CN **must match** the Publisher in your `AppxManifest.xml`:

```xml
<Identity Name="YourApp" Publisher="CN=YourCompany" Version="1.0.0.0" />
```

### Using PowerShell

```powershell
# Create certificate (CN must match Publisher in manifest)
$cert = New-SelfSignedCertificate -Type Custom -Subject "CN=YourCompany" `
    -KeyUsage DigitalSignature -FriendlyName "MSIX Test Certificate" `
    -CertStoreLocation "Cert:\CurrentUser\My" `
    -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.3", "2.5.29.19={text}")

# Export to PFX
$password = ConvertTo-SecureString -String "YourPassword" -Force -AsPlainText
Export-PfxCertificate -Cert $cert -FilePath ".\test-certificate.pfx" -Password $password

# Install to Trusted Root (required for local testing)
$store = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "LocalMachine")
$store.Open("ReadWrite")
$store.Add($cert)
$store.Close()
```

### Using OpenSSL

```bash
# Generate key and certificate
openssl genrsa -out private.key 2048
openssl req -new -key private.key -out request.csr -subj "/CN=YourCompany"
openssl x509 -req -days 365 -in request.csr -signkey private.key -out certificate.crt

# Export to PFX
openssl pkcs12 -export -out test-certificate.pfx -inkey private.key -in certificate.crt -password pass:YourPassword
```

## Notes

- **Microsoft Store**: No certificate needed - submit unsigned packages, the Store signs them
- **Enterprise/Sideloading**: Use a certificate from a trusted Certificate Authority
- **Local Testing**: Self-signed certificates work after installing to Trusted Root

## Requirements

- Windows OS with Windows SDK 10 installed
- MakeAppx.exe and signtool.exe
- makepri.exe (optional, required only with `--makepri`)
- WACK (appcert.exe) for `--validate` option

## License

MIT License
