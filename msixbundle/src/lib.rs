//! A Rust library for building and signing Windows MSIX packages and bundles.
//!
//! This library provides a programmatic interface to create multi-architecture MSIX packages
//! and combine them into MSIX bundles using the Windows SDK toolchain (MakeAppx.exe and SignTool.exe).
//!
//! # Features
//!
//! - Automatic Windows SDK tool discovery via registry
//! - Manifest parsing from AppxManifest.xml files
//! - Multi-architecture package creation (x64, ARM64, etc.)
//! - Bundle creation from multiple architecture packages
//! - Code signing with PFX certificates or certificate store thumbprints
//! - Timestamping support (RFC3161 and Authenticode)
//! - Package validation and signature verification
//!
//! # Example
//!
//! ```no_run
//! use msixbundle::*;
//! use std::path::Path;
//!
//! # fn main() -> anyhow::Result<()> {
//! // Locate Windows SDK tools automatically
//! let tools = locate_sdk_tools()?;
//!
//! // Read manifest information
//! let app_dir = Path::new("./AppxContent");
//! let manifest = read_manifest_info(app_dir)?;
//!
//! // Pack a single architecture
//! let out_dir = Path::new("./output");
//! let msix = pack_arch(&tools, app_dir, out_dir, &manifest, "x64", true)?;
//!
//! println!("Created: {}", msix.display());
//! # Ok(())
//! # }
//! ```

use anyhow::{Context, Result};
use std::{
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    process::Command,
};
use thiserror::Error;

/// Dotted-quad version for SDK folder parsing (e.g., "10.0.19041.0").
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
struct Version4(u32, u32, u32, u32);

impl Version4 {
    fn parse(s: &str) -> Result<Self, ()> {
        let mut it = s.split('.');
        let a = it.next().ok_or(())?.parse().map_err(|_| ())?;
        let b = it.next().ok_or(())?.parse().map_err(|_| ())?;
        let c = it.next().ok_or(())?.parse().map_err(|_| ())?;
        let d = it.next().ok_or(())?.parse().map_err(|_| ())?;
        if it.next().is_some() {
            return Err(());
        }
        Ok(Self(a, b, c, d))
    }
}

/// Errors that can occur during MSIX packaging operations.
#[derive(Debug, Error)]
pub enum MsixError {
    /// A required Windows SDK tool (MakeAppx.exe or SignTool.exe) was not found.
    #[error("Windows SDK tool not found: {0}")]
    ToolMissing(&'static str),
    /// MakeAppx.exe operation failed (pack, bundle, or validate).
    #[error("MakeAppx failed: {0}")]
    MakeAppx(String),
    /// SignTool.exe operation failed (sign or verify).
    #[error("SignTool failed: {0}")]
    SignTool(String),
    /// Failed to parse AppxManifest.xml.
    #[error("Manifest parse error: {0}")]
    Manifest(String),
    /// WACK validation failed.
    #[error("Validation failed: {0}")]
    Validation(String),
    /// Other miscellaneous error.
    #[error("{0}")]
    Other(String),
}

/// Certificate source for signing operations.
///
/// Specifies how to locate the signing certificate - either from a PFX file
/// or from the Windows certificate store using a thumbprint.
#[derive(Clone, Debug)]
pub enum CertificateSource<'a> {
    /// PFX file with optional password.
    Pfx {
        /// Path to the .pfx certificate file.
        path: &'a Path,
        /// Password for the PFX file (if encrypted).
        password: Option<&'a str>,
    },
    /// Certificate from Windows certificate store identified by thumbprint.
    Thumbprint {
        /// SHA1 thumbprint of the certificate (40 hex characters).
        sha1: &'a str,
        /// Certificate store name. Common values: "My" (Personal), "Root", "CA".
        /// See: <https://learn.microsoft.com/en-us/dotnet/framework/tools/signtool-exe>
        store: Option<&'a str>,
        /// Use machine store instead of current user store.
        machine_store: bool,
    },
}

/// Paths to Windows SDK tools (MakeAppx.exe, SignTool.exe, and appcert.exe).
///
/// This struct holds the absolute paths to the Windows SDK executables needed
/// for creating, signing, and validating MSIX packages.
#[derive(Clone, Debug)]
pub struct SdkTools {
    /// Path to MakeAppx.exe (required for pack and bundle operations).
    pub makeappx: PathBuf,
    /// Path to SignTool.exe (optional, only needed for signing operations).
    pub signtool: Option<PathBuf>,
    /// Path to appcert.exe (optional, only needed for WACK validation).
    pub appcert: Option<PathBuf>,
}

/// Automatically locates Windows SDK tools on the system.
///
/// Searches the Windows registry for installed Windows SDK versions and returns
/// paths to the latest version of MakeAppx.exe and SignTool.exe found in the
/// `C:\Program Files (x86)\Windows Kits\10\bin\` directory.
///
/// # Requirements
///
/// - Windows OS
/// - Windows SDK 10 installed
/// - `sdk-discovery` feature enabled (default)
///
/// # Returns
///
/// Returns [`SdkTools`] containing paths to MakeAppx.exe and optionally SignTool.exe.
///
/// # Errors
///
/// Returns an error if:
/// - Windows Kits registry key cannot be opened
/// - No valid SDK installation with MakeAppx.exe is found
///
/// # Example
///
/// ```no_run
/// use msixbundle::locate_sdk_tools;
///
/// # fn main() -> anyhow::Result<()> {
/// let tools = locate_sdk_tools()?;
/// println!("MakeAppx: {}", tools.makeappx.display());
/// if let Some(signtool) = &tools.signtool {
///     println!("SignTool: {}", signtool.display());
/// }
/// # Ok(())
/// # }
/// ```
#[cfg(all(feature = "sdk-discovery", target_os = "windows"))]
pub fn locate_sdk_tools() -> Result<SdkTools> {
    use winreg::{enums::HKEY_LOCAL_MACHINE, RegKey};
    let roots = RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey("SOFTWARE\\Microsoft\\Windows Kits\\Installed Roots")
        .context("open Windows Kits registry")?;
    let kits_root10: String = roots.get_value("KitsRoot10").context("read KitsRoot10")?;
    let bin_dir = PathBuf::from(kits_root10).join("bin");

    let mut best: Option<(Version4, PathBuf)> = None;
    for e in fs::read_dir(&bin_dir).context("list SDK bin")? {
        let e = e?;
        if !e.file_type()?.is_dir() {
            continue;
        }
        let name = e.file_name().to_string_lossy().into_owned();
        if let Ok(v) = Version4::parse(&name) {
            let makeappx = e.path().join("x64").join("MakeAppx.exe");
            if makeappx.exists() {
                if let Some((bv, _)) = &best {
                    if v > *bv {
                        best = Some((v, e.path()));
                    }
                } else {
                    best = Some((v, e.path()));
                }
            }
        }
    }
    let base = best
        .map(|(_, p)| p)
        .ok_or(MsixError::ToolMissing("MakeAppx.exe"))?;
    let makeappx = base.join("x64").join("MakeAppx.exe");
    let signtool = {
        let p = base.join("x64").join("signtool.exe");
        if p.exists() {
            Some(p)
        } else {
            None
        }
    };
    // WACK (Windows App Certification Kit) is in a separate directory
    let appcert = {
        let kits_root10: String = roots.get_value("KitsRoot10").context("read KitsRoot10")?;
        let p = PathBuf::from(kits_root10)
            .join("App Certification Kit")
            .join("appcert.exe");
        if p.exists() {
            Some(p)
        } else {
            None
        }
    };
    Ok(SdkTools {
        makeappx,
        signtool,
        appcert,
    })
}

/// Information extracted from an AppxManifest.xml file.
///
/// Contains the application version and display name used for naming output files.
#[derive(Clone, Debug)]
pub struct ManifestInfo {
    /// Application version from the `<Identity Version="...">` attribute.
    pub version: String,
    /// Sanitized display name from `<DisplayName>` or fallback to Identity Name.
    pub display_name: String,
}

/// Reads and parses AppxManifest.xml to extract version and display name.
///
/// Reads the `AppxManifest.xml` file from the specified AppxContent directory
/// and extracts the application version and display name. The display name is
/// sanitized to remove invalid filename characters.
///
/// # Arguments
///
/// * `appx_content_dir` - Path to directory containing AppxManifest.xml
///
/// # Returns
///
/// Returns [`ManifestInfo`] containing the version and display name.
///
/// # Errors
///
/// Returns an error if:
/// - AppxManifest.xml file cannot be read
/// - XML parsing fails
/// - Required elements (`<Package>`, `<Identity>`) are missing
/// - Version attribute is missing
///
/// # Example
///
/// ```no_run
/// use msixbundle::read_manifest_info;
/// use std::path::Path;
///
/// # fn main() -> anyhow::Result<()> {
/// let info = read_manifest_info(Path::new("./AppxContent"))?;
/// println!("App: {} v{}", info.display_name, info.version);
/// # Ok(())
/// # }
/// ```
pub fn read_manifest_info(appx_content_dir: &Path) -> Result<ManifestInfo> {
    let path = appx_content_dir.join("AppxManifest.xml");
    let xml = fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    let doc = roxmltree::Document::parse(&xml).map_err(|e| MsixError::Manifest(e.to_string()))?;
    let pkg = doc
        .descendants()
        .find(|n| n.has_tag_name("Package"))
        .ok_or_else(|| MsixError::Manifest("missing <Package>".into()))?;
    let id = pkg
        .children()
        .find(|n| n.has_tag_name("Identity"))
        .ok_or_else(|| MsixError::Manifest("missing <Identity>".into()))?;
    let version = id
        .attribute("Version")
        .ok_or_else(|| MsixError::Manifest("Identity@Version missing".into()))?
        .to_string();
    let identity_name = id.attribute("Name").unwrap_or("App").to_string();
    let display = pkg
        .children()
        .find(|n| n.has_tag_name("Properties"))
        .and_then(|p| p.children().find(|n| n.has_tag_name("DisplayName")))
        .and_then(|n| n.text())
        .map(|s| s.trim().to_string());
    let final_name = match display {
        Some(s) if !s.is_empty() && !s.starts_with("ms-resource:") => s,
        _ => identity_name,
    };
    Ok(ManifestInfo {
        version,
        display_name: sanitize(&final_name),
    })
}

fn sanitize(s: &str) -> String {
    let bad = ['<', '>', ':', '"', '/', '\\', '|', '?', '*'];
    let mut out = String::new();
    for ch in s.chars() {
        if !bad.contains(&ch) {
            out.push(ch);
        }
    }
    if out.is_empty() {
        "App".into()
    } else {
        out
    }
}

/// Creates a .msix package for a specific architecture.
///
/// Invokes MakeAppx.exe to pack the contents of an AppxContent directory into
/// a .msix file with SHA256 hashing. The output file is named using the pattern:
/// `{DisplayName}_{Version}_{arch}.msix`
///
/// # Arguments
///
/// * `tools` - SDK tools paths from [`locate_sdk_tools()`]
/// * `appx_dir` - Path to AppxContent directory (must contain AppxManifest.xml)
/// * `out_dir` - Directory where the .msix file will be created
/// * `info` - Manifest info from [`read_manifest_info()`]
/// * `arch` - Architecture identifier (e.g., "x64", "arm64", "x86")
/// * `overwrite` - If `true`, overwrite existing output file
///
/// # Returns
///
/// Returns the path to the created .msix file.
///
/// # Errors
///
/// Returns an error if:
/// - MakeAppx.exe execution fails
/// - Output directory is not writable
///
/// # Example
///
/// ```no_run
/// use msixbundle::*;
/// use std::path::Path;
///
/// # fn main() -> anyhow::Result<()> {
/// let tools = locate_sdk_tools()?;
/// let dir = Path::new("./AppxContent");
/// let info = read_manifest_info(dir)?;
/// let out = Path::new("./output");
///
/// let msix = pack_arch(&tools, dir, out, &info, "x64", false)?;
/// println!("Created: {}", msix.display());
/// # Ok(())
/// # }
/// ```
pub fn pack_arch(
    tools: &SdkTools,
    appx_dir: &Path,
    out_dir: &Path,
    info: &ManifestInfo,
    arch: &str,
    overwrite: bool,
) -> Result<PathBuf> {
    let out = out_dir.join(format!(
        "{}_{}_{}.msix",
        info.display_name, info.version, arch
    ));
    let mut args: Vec<OsString> = vec![
        "pack".into(),
        "/d".into(),
        appx_dir.as_os_str().into(),
        "/p".into(),
        out.as_os_str().into(),
        "/h".into(),
        "SHA256".into(),
    ];
    if overwrite {
        args.push("/o".into());
    } else {
        args.push("/no".into());
    }
    let status = Command::new(&tools.makeappx)
        .args(args)
        .status()
        .context("run MakeAppx pack")?;
    if !status.success() {
        return Err(MsixError::MakeAppx(format!("pack {arch}")).into());
    }
    Ok(out)
}

/// Creates a .msixbundle from multiple architecture-specific .msix packages.
///
/// Generates a bundlemap.txt file and invokes MakeAppx.exe to bundle multiple
/// .msix files into a single .msixbundle. The output file is named:
/// `{DisplayName}_{Version}.msixbundle`
///
/// # Arguments
///
/// * `tools` - SDK tools paths from [`locate_sdk_tools()`]
/// * `out_dir` - Directory where the .msixbundle and bundlemap.txt will be created
/// * `built` - Vector of (architecture, .msix path) tuples from [`pack_arch()`]
/// * `info` - Manifest info from [`read_manifest_info()`]
/// * `overwrite` - If `true`, overwrite existing output file
///
/// # Returns
///
/// Returns the path to the created .msixbundle file.
///
/// # Errors
///
/// Returns an error if:
/// - bundlemap.txt cannot be written
/// - MakeAppx.exe bundle operation fails
///
/// # Example
///
/// ```no_run
/// use msixbundle::*;
/// use std::path::{Path, PathBuf};
///
/// # fn main() -> anyhow::Result<()> {
/// let tools = locate_sdk_tools()?;
/// let out = Path::new("./output");
///
/// let packages = vec![
///     ("x64".to_string(), PathBuf::from("./output/App_1.0.0_x64.msix")),
///     ("arm64".to_string(), PathBuf::from("./output/App_1.0.0_arm64.msix")),
/// ];
///
/// let info = read_manifest_info(Path::new("./AppxContent"))?;
/// let bundle = build_bundle(&tools, out, &packages, &info, false)?;
/// println!("Bundle: {}", bundle.display());
/// # Ok(())
/// # }
/// ```
pub fn build_bundle(
    tools: &SdkTools,
    out_dir: &Path,
    built: &[(String, PathBuf)],
    info: &ManifestInfo,
    overwrite: bool,
) -> Result<PathBuf> {
    let map = out_dir.join("bundlemap.txt");
    let mut s = String::from("[Files]\n");
    for (_arch, path) in built {
        let filename = path
            .file_name()
            .map(|f| f.to_string_lossy())
            .unwrap_or_else(|| path.to_string_lossy());
        s.push('"');
        s.push_str(&path.to_string_lossy());
        s.push('"');
        s.push(' ');
        s.push('"');
        s.push_str(&filename);
        s.push('"');
        s.push('\n');
    }
    fs::write(&map, s).context("write bundlemap.txt")?;
    let bundle = out_dir.join(format!("{}_{}.msixbundle", info.display_name, info.version));
    let mut args: Vec<OsString> = vec![
        "bundle".into(),
        "/f".into(),
        map.as_os_str().into(),
        "/p".into(),
        bundle.as_os_str().into(),
        "/bv".into(),
        info.version.clone().into(),
    ];
    if overwrite {
        args.push("/o".into());
    } else {
        args.push("/no".into());
    }
    let status = Command::new(&tools.makeappx)
        .args(args)
        .status()
        .context("run MakeAppx bundle")?;
    if !status.success() {
        return Err(MsixError::MakeAppx("bundle".into()).into());
    }
    Ok(bundle)
}

/// Options for signing MSIX packages or bundles with SignTool.exe.
///
/// Configures certificate source, timestamping, and other signing parameters.
pub struct SignOptions<'a> {
    /// Path to the .msix, .msixbundle, or other artifact to sign.
    pub artifact: &'a Path,
    /// Certificate source (PFX file or thumbprint from certificate store).
    pub certificate: CertificateSource<'a>,
    /// Path to AppxSip.dll (e.g., `C:\Windows\System32\AppxSip.dll`).
    /// Used to force the correct Subject Interface Package for MSIX signing.
    pub sip_dll: Option<&'a Path>,
    /// Timestamp server URL (e.g., `http://timestamp.digicert.com`).
    /// Set to `None` to skip timestamping.
    pub timestamp_url: Option<&'a str>,
    /// If `true`, use RFC3161 timestamping (`/tr /td SHA256`).
    /// If `false`, use legacy Authenticode timestamping (`/t`).
    pub rfc3161: bool,
    /// Override path to signtool.exe (useful if not using auto-discovered SDK tools).
    pub signtool_override: Option<&'a Path>,
}

/// Signs a .msix package or .msixbundle using a certificate.
///
/// Invokes SignTool.exe to apply a digital signature using SHA256 hashing.
/// Supports both PFX file certificates and certificates from the Windows
/// certificate store (identified by thumbprint).
///
/// # Arguments
///
/// * `tools` - SDK tools paths (signtool.exe must be available)
/// * `opts` - Signing options including certificate source and timestamp settings
///
/// # Errors
///
/// Returns an error if:
/// - SignTool.exe is not found in SDK tools or override path
/// - SignTool.exe execution fails
/// - Certificate file is invalid or password is incorrect
/// - Certificate thumbprint not found in store
///
/// # Examples
///
/// ## Signing with PFX file
///
/// ```no_run
/// use msixbundle::*;
/// use std::path::Path;
///
/// # fn main() -> anyhow::Result<()> {
/// let tools = locate_sdk_tools()?;
/// let bundle = Path::new("./output/App_1.0.0.msixbundle");
///
/// sign_artifact(&tools, &SignOptions {
///     artifact: bundle,
///     certificate: CertificateSource::Pfx {
///         path: Path::new("./signing.pfx"),
///         password: Some("password"),
///     },
///     sip_dll: None,
///     timestamp_url: Some("http://timestamp.digicert.com"),
///     rfc3161: true,
///     signtool_override: None,
/// })?;
/// # Ok(())
/// # }
/// ```
///
/// ## Signing with certificate thumbprint
///
/// ```no_run
/// use msixbundle::*;
/// use std::path::Path;
///
/// # fn main() -> anyhow::Result<()> {
/// let tools = locate_sdk_tools()?;
/// let bundle = Path::new("./output/App_1.0.0.msixbundle");
///
/// sign_artifact(&tools, &SignOptions {
///     artifact: bundle,
///     certificate: CertificateSource::Thumbprint {
///         sha1: "1a2b3c4d5e6f...",
///         store: Some("My"),
///         machine_store: false,
///     },
///     sip_dll: None,
///     timestamp_url: Some("http://timestamp.digicert.com"),
///     rfc3161: true,
///     signtool_override: None,
/// })?;
/// # Ok(())
/// # }
/// ```
pub fn sign_artifact(tools: &SdkTools, opts: &SignOptions<'_>) -> Result<()> {
    let signtool = opts
        .signtool_override
        .or(tools.signtool.as_deref())
        .ok_or(MsixError::ToolMissing("signtool.exe"))?;

    let args = build_sign_args(opts);

    let status = Command::new(signtool)
        .args(args)
        .status()
        .context("run signtool sign")?;
    if !status.success() {
        return Err(MsixError::SignTool(format!("sign {}", opts.artifact.display())).into());
    }
    Ok(())
}

/// Builds the command-line arguments for SignTool sign command.
fn build_sign_args(opts: &SignOptions<'_>) -> Vec<OsString> {
    let mut args: Vec<OsString> = vec!["sign".into(), "/fd".into(), "SHA256".into()];

    // Add certificate-specific arguments
    match &opts.certificate {
        CertificateSource::Pfx { path, password } => {
            args.push("/f".into());
            args.push(path.as_os_str().into());
            if let Some(pw) = password {
                args.push("/p".into());
                args.push(OsString::from(*pw));
            }
        }
        CertificateSource::Thumbprint {
            sha1,
            store,
            machine_store,
        } => {
            args.push("/sha1".into());
            args.push(OsString::from(*sha1));
            if let Some(s) = store {
                args.push("/s".into());
                args.push(OsString::from(*s));
            }
            if *machine_store {
                args.push("/sm".into());
            }
        }
    }

    if let Some(sip) = opts.sip_dll {
        args.push("/dlib".into());
        args.push(sip.as_os_str().into());
    }
    if let Some(url) = opts.timestamp_url {
        if opts.rfc3161 {
            args.extend(["/td".into(), "SHA256".into(), "/tr".into(), url.into()]);
        } else {
            args.extend(["/t".into(), url.into()]);
        }
    }
    args.push(opts.artifact.as_os_str().into());

    args
}

/// Verifies the digital signature of a signed .msix or .msixbundle.
///
/// Invokes SignTool.exe with the `/pa` flag to verify using the Appx/MSIX policy,
/// which checks that the signature is valid and trusted for Windows app packages.
///
/// # Arguments
///
/// * `tools` - SDK tools paths (signtool.exe must be available)
/// * `artifact` - Path to the signed .msix or .msixbundle file
///
/// # Errors
///
/// Returns an error if:
/// - SignTool.exe is not found
/// - Signature verification fails (invalid, untrusted, or missing signature)
///
/// # Example
///
/// ```no_run
/// use msixbundle::*;
/// use std::path::Path;
///
/// # fn main() -> anyhow::Result<()> {
/// let tools = locate_sdk_tools()?;
/// let bundle = Path::new("./output/App_1.0.0.msixbundle");
///
/// verify_signature(&tools, bundle)?;
/// println!("Signature is valid!");
/// # Ok(())
/// # }
/// ```
pub fn verify_signature(tools: &SdkTools, artifact: &Path) -> Result<()> {
    let signtool = tools
        .signtool
        .as_ref()
        .ok_or(MsixError::ToolMissing("signtool.exe"))?;
    let status = Command::new(signtool)
        .args(["verify", "/pa", "/v", &artifact.to_string_lossy()])
        .status()
        .context("run signtool verify")?;
    if !status.success() {
        return Err(MsixError::SignTool(format!("verify {}", artifact.display())).into());
    }
    Ok(())
}

/// Validates a .msix package or .msixbundle using Windows App Certification Kit (WACK).
///
/// Invokes appcert.exe to perform comprehensive validation including:
/// - Package structure and manifest validation
/// - App capabilities and security checks
/// - Microsoft Store submission requirements
///
/// **Note:** This function requires administrator privileges on Windows.
/// On GitHub Actions Windows runners, UAC is disabled and validation works automatically.
///
/// # Arguments
///
/// * `tools` - SDK tools paths (appcert.exe must be available)
/// * `msix_or_bundle` - Path to the .msix or .msixbundle file to validate
///
/// # Errors
///
/// Returns an error if:
/// - appcert.exe (WACK) is not found
/// - Validation fails (package doesn't meet requirements)
/// - Process execution fails (may happen without admin privileges)
///
/// # Example
///
/// ```no_run
/// use msixbundle::*;
/// use std::path::Path;
///
/// # fn main() -> anyhow::Result<()> {
/// let tools = locate_sdk_tools()?;
/// let bundle = Path::new("./output/App_1.0.0.msixbundle");
///
/// validate_package(&tools, bundle)?;
/// println!("Package passed WACK validation!");
/// # Ok(())
/// # }
/// ```
pub fn validate_package(tools: &SdkTools, msix_or_bundle: &Path) -> Result<()> {
    let appcert = tools
        .appcert
        .as_ref()
        .ok_or(MsixError::ToolMissing("appcert.exe (WACK)"))?;

    // Use unique report file to avoid conflicts with previous runs
    let report_file = std::env::temp_dir().join(format!("wack_report_{}.xml", std::process::id()));
    // Remove existing report file if present
    let _ = fs::remove_file(&report_file);

    let status = Command::new(appcert)
        .args([
            "test",
            "-appxpackagepath",
            &msix_or_bundle.to_string_lossy(),
            "-reportoutputpath",
            &report_file.to_string_lossy(),
        ])
        .status()
        .context("run appcert (WACK)")?;

    if !status.success() {
        return Err(MsixError::Validation(msix_or_bundle.display().to_string()).into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_removes_invalid_chars() {
        assert_eq!(sanitize("My:App"), "MyApp");
        assert_eq!(sanitize("App<>Name"), "AppName");
        assert_eq!(sanitize("Test/App\\Name"), "TestAppName");
    }

    #[test]
    fn sanitize_returns_app_for_empty() {
        assert_eq!(sanitize(""), "App");
        assert_eq!(sanitize(":::"), "App");
    }

    #[test]
    fn sanitize_preserves_valid_chars() {
        assert_eq!(sanitize("MyApp 2.0"), "MyApp 2.0");
        assert_eq!(sanitize("App-Name_v1"), "App-Name_v1");
    }

    #[test]
    fn version4_parse_valid() {
        let v = Version4::parse("10.0.19041.0").expect("valid version");
        assert_eq!(v, Version4(10, 0, 19041, 0));
    }

    #[test]
    fn version4_parse_invalid() {
        assert!(Version4::parse("10.0.19041").is_err()); // too few parts
        assert!(Version4::parse("10.0.19041.0.0").is_err()); // too many parts
        assert!(Version4::parse("abc").is_err());
    }

    #[test]
    fn version4_ordering() {
        let v1 = Version4::parse("10.0.19041.0").expect("v1");
        let v2 = Version4::parse("10.0.22000.0").expect("v2");
        assert!(v2 > v1);
    }

    #[test]
    fn read_manifest_info_valid() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let manifest = r#"<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10">
  <Identity Name="MyCompany.MyApp" Version="1.2.3.0" Publisher="CN=Test"/>
  <Properties>
    <DisplayName>My Cool App</DisplayName>
  </Properties>
</Package>"#;
        std::fs::write(dir.path().join("AppxManifest.xml"), manifest).expect("write manifest");

        let info = read_manifest_info(dir.path()).expect("parse manifest");
        assert_eq!(info.version, "1.2.3.0");
        assert_eq!(info.display_name, "My Cool App");
    }

    #[test]
    fn read_manifest_info_ms_resource_fallback() {
        // When DisplayName is "ms-resource:..." should fall back to Identity Name
        let dir = tempfile::tempdir().expect("create temp dir");
        let manifest = r#"<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10">
  <Identity Name="MyCompany.MyApp" Version="1.0.0.0" Publisher="CN=Test"/>
  <Properties>
    <DisplayName>ms-resource:AppName</DisplayName>
  </Properties>
</Package>"#;
        std::fs::write(dir.path().join("AppxManifest.xml"), manifest).expect("write manifest");

        let info = read_manifest_info(dir.path()).expect("parse manifest");
        assert_eq!(info.display_name, "MyCompany.MyApp");
    }

    // Helper to convert OsString vec to String vec for easier assertions
    fn args_to_strings(args: Vec<OsString>) -> Vec<String> {
        args.into_iter()
            .map(|s| s.to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn build_sign_args_pfx_with_password() {
        let artifact = Path::new("test.msix");
        let pfx = Path::new("cert.pfx");
        let opts = SignOptions {
            artifact,
            certificate: CertificateSource::Pfx {
                path: pfx,
                password: Some("secret"),
            },
            sip_dll: None,
            timestamp_url: None,
            rfc3161: true,
            signtool_override: None,
        };
        let args = args_to_strings(build_sign_args(&opts));
        assert_eq!(
            args,
            vec![
                "sign",
                "/fd",
                "SHA256",
                "/f",
                "cert.pfx",
                "/p",
                "secret",
                "test.msix"
            ]
        );
    }

    #[test]
    fn build_sign_args_pfx_without_password() {
        let artifact = Path::new("test.msix");
        let pfx = Path::new("cert.pfx");
        let opts = SignOptions {
            artifact,
            certificate: CertificateSource::Pfx {
                path: pfx,
                password: None,
            },
            sip_dll: None,
            timestamp_url: None,
            rfc3161: true,
            signtool_override: None,
        };
        let args = args_to_strings(build_sign_args(&opts));
        assert_eq!(
            args,
            vec!["sign", "/fd", "SHA256", "/f", "cert.pfx", "test.msix"]
        );
    }

    #[test]
    fn build_sign_args_thumbprint_default_store() {
        let artifact = Path::new("test.msix");
        let opts = SignOptions {
            artifact,
            certificate: CertificateSource::Thumbprint {
                sha1: "ABC123",
                store: Some("My"),
                machine_store: false,
            },
            sip_dll: None,
            timestamp_url: None,
            rfc3161: true,
            signtool_override: None,
        };
        let args = args_to_strings(build_sign_args(&opts));
        assert_eq!(
            args,
            vec![
                "sign",
                "/fd",
                "SHA256",
                "/sha1",
                "ABC123",
                "/s",
                "My",
                "test.msix"
            ]
        );
    }

    #[test]
    fn build_sign_args_thumbprint_custom_store() {
        let artifact = Path::new("test.msix");
        let opts = SignOptions {
            artifact,
            certificate: CertificateSource::Thumbprint {
                sha1: "ABC123",
                store: Some("Root"),
                machine_store: false,
            },
            sip_dll: None,
            timestamp_url: None,
            rfc3161: true,
            signtool_override: None,
        };
        let args = args_to_strings(build_sign_args(&opts));
        assert_eq!(
            args,
            vec![
                "sign",
                "/fd",
                "SHA256",
                "/sha1",
                "ABC123",
                "/s",
                "Root",
                "test.msix"
            ]
        );
    }

    #[test]
    fn build_sign_args_thumbprint_machine_store() {
        let artifact = Path::new("test.msix");
        let opts = SignOptions {
            artifact,
            certificate: CertificateSource::Thumbprint {
                sha1: "ABC123",
                store: Some("My"),
                machine_store: true,
            },
            sip_dll: None,
            timestamp_url: None,
            rfc3161: true,
            signtool_override: None,
        };
        let args = args_to_strings(build_sign_args(&opts));
        assert_eq!(
            args,
            vec![
                "sign",
                "/fd",
                "SHA256",
                "/sha1",
                "ABC123",
                "/s",
                "My",
                "/sm",
                "test.msix"
            ]
        );
    }

    #[test]
    fn build_sign_args_thumbprint_no_store() {
        let artifact = Path::new("test.msix");
        let opts = SignOptions {
            artifact,
            certificate: CertificateSource::Thumbprint {
                sha1: "ABC123",
                store: None,
                machine_store: false,
            },
            sip_dll: None,
            timestamp_url: None,
            rfc3161: true,
            signtool_override: None,
        };
        let args = args_to_strings(build_sign_args(&opts));
        assert_eq!(
            args,
            vec!["sign", "/fd", "SHA256", "/sha1", "ABC123", "test.msix"]
        );
    }

    #[test]
    fn build_sign_args_with_timestamp_rfc3161() {
        let artifact = Path::new("test.msix");
        let pfx = Path::new("cert.pfx");
        let opts = SignOptions {
            artifact,
            certificate: CertificateSource::Pfx {
                path: pfx,
                password: None,
            },
            sip_dll: None,
            timestamp_url: Some("http://timestamp.example.com"),
            rfc3161: true,
            signtool_override: None,
        };
        let args = args_to_strings(build_sign_args(&opts));
        assert_eq!(
            args,
            vec![
                "sign",
                "/fd",
                "SHA256",
                "/f",
                "cert.pfx",
                "/td",
                "SHA256",
                "/tr",
                "http://timestamp.example.com",
                "test.msix"
            ]
        );
    }

    #[test]
    fn build_sign_args_with_timestamp_authenticode() {
        let artifact = Path::new("test.msix");
        let pfx = Path::new("cert.pfx");
        let opts = SignOptions {
            artifact,
            certificate: CertificateSource::Pfx {
                path: pfx,
                password: None,
            },
            sip_dll: None,
            timestamp_url: Some("http://timestamp.example.com"),
            rfc3161: false,
            signtool_override: None,
        };
        let args = args_to_strings(build_sign_args(&opts));
        assert_eq!(
            args,
            vec![
                "sign",
                "/fd",
                "SHA256",
                "/f",
                "cert.pfx",
                "/t",
                "http://timestamp.example.com",
                "test.msix"
            ]
        );
    }
}
