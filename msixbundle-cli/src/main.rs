use anyhow::{bail, Result};
use clap::Parser;
use log::{info, warn};
use std::path::PathBuf;

use msixbundle::*;

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    /// Output directory for .msix/.msixbundle
    #[arg(long)]
    out_dir: PathBuf,

    /// AppxContent dir for x64 (contains AppxManifest.xml)
    #[arg(long)]
    dir_x64: Option<PathBuf>,

    /// AppxContent dir for arm64
    #[arg(long)]
    dir_arm64: Option<PathBuf>,

    /// PFX certificate file for signing (mutually exclusive with --thumbprint)
    #[arg(long, conflicts_with = "thumbprint")]
    pfx: Option<PathBuf>,

    /// PFX password
    #[arg(long, requires = "pfx")]
    pfx_password: Option<String>,

    /// Certificate thumbprint (SHA1) from Windows cert store (mutually exclusive with --pfx)
    #[arg(long, conflicts_with = "pfx")]
    thumbprint: Option<String>,

    /// Certificate store name. Common: "My" (Personal), "Root", "CA".
    /// See: https://learn.microsoft.com/en-us/dotnet/framework/tools/signtool-exe
    #[arg(long, default_value = "My", requires = "thumbprint")]
    cert_store: String,

    /// Use machine certificate store instead of user store
    #[arg(long, requires = "thumbprint")]
    machine_store: bool,

    /// Also sign per-arch .msix
    #[arg(long, default_value_t = false)]
    sign_each: bool,

    /// Override signtool.exe path
    #[arg(long)]
    signtool_path: Option<PathBuf>,

    /// Force Appx SIP DLL (e.g. C:\Windows\System32\AppxSip.dll)
    #[arg(long)]
    sip_dll: Option<PathBuf>,

    /// Timestamp URL (set empty to skip)
    #[arg(long, default_value = "http://timestamp.digicert.com")]
    timestamp_url: String,

    /// Timestamp mode: rfc3161 | authenticode
    #[arg(long, value_parser = ["rfc3161","authenticode"], default_value = "rfc3161")]
    timestamp_mode: String,

    /// Validate packages with MakeAppx after build
    #[arg(long)]
    validate: bool,

    /// Verify signatures with SignTool after signing
    #[arg(long)]
    verify: bool,

    /// Increase verbosity (RUST_LOG=info)
    #[arg(long)]
    verbose: bool,

    /// Overwrite existing output files
    #[arg(long)]
    force: bool,
}

/// Resolve path to absolute, stripping Windows extended-length prefix (\\?\)
fn resolve_path(p: &std::path::Path) -> Result<PathBuf> {
    let abs = p.canonicalize()?;
    let s = abs.to_string_lossy();
    if let Some(stripped) = s.strip_prefix(r"\\?\") {
        Ok(PathBuf::from(stripped))
    } else {
        Ok(abs)
    }
}

fn main() -> Result<()> {
    let a = Args::parse();
    if a.verbose {
        std::env::set_var("RUST_LOG", "info");
    }
    env_logger::init();

    if a.dir_x64.is_none() && a.dir_arm64.is_none() {
        bail!("Provide at least one of --dir-x64 or --dir-arm64");
    }
    std::fs::create_dir_all(&a.out_dir)?;
    let out_dir = resolve_path(&a.out_dir)?;

    let mut tools = locate_sdk_tools()?;
    if let Some(p) = &a.signtool_path {
        tools.signtool = Some(p.clone());
    }

    // Pack per-arch
    let mut built: Vec<(String, PathBuf)> = Vec::new();
    let mut info: Option<ManifestInfo> = None;

    if let Some(dir) = &a.dir_x64 {
        let dir = resolve_path(dir)?;
        let m = read_manifest_info(&dir)?;
        info = Some(m.clone());
        info!("x64: {}", dir.display());
        let msix = pack_arch(&tools, &dir, &out_dir, &m, "x64", a.force)?;
        built.push(("x64".into(), msix));
    }

    if let Some(dir) = &a.dir_arm64 {
        let dir = resolve_path(dir)?;
        let m = read_manifest_info(&dir)?;
        if let Some(i) = &info {
            if i.version != m.version {
                bail!(
                    "Version mismatch: manifests differ ({} vs {})",
                    i.version,
                    m.version
                );
            }
        } else {
            info = Some(m.clone());
        }
        info!("arm64: {}", dir.display());
        let msix = pack_arch(&tools, &dir, &out_dir, &m, "arm64", a.force)?;
        built.push(("arm64".into(), msix));
    }

    let info = info.expect("manifest info");
    if a.validate {
        for (_, p) in &built {
            validate_package(&tools, p)?;
        }
    }

    // Determine certificate source for signing
    let cert_source: Option<CertificateSource> = if let Some(pfx) = &a.pfx {
        Some(CertificateSource::Pfx {
            path: pfx,
            password: a.pfx_password.as_deref(),
        })
    } else if let Some(thumbprint) = &a.thumbprint {
        Some(CertificateSource::Thumbprint {
            sha1: thumbprint,
            store: Some(a.cert_store.as_str()),
            machine_store: a.machine_store,
        })
    } else {
        None
    };

    // Sign per-arch (optional, often skipped)
    if a.sign_each {
        if let Some(ref cert) = cert_source {
            for (_, msix) in &built {
                sign_artifact(
                    &tools,
                    &SignOptions {
                        artifact: msix,
                        certificate: cert.clone(),
                        sip_dll: a.sip_dll.as_deref(),
                        timestamp_url: None, // usually skip timestamp on inner packages
                        rfc3161: true,
                        signtool_override: a.signtool_path.as_deref(),
                    },
                )?;
                if a.verify {
                    verify_signature(&tools, msix)?;
                }
            }
        } else {
            warn!("--sign-each set but no --pfx or --thumbprint; skipping per-arch signing");
        }
    }

    // Bundle
    let bundle = build_bundle(&tools, &out_dir, &built, &info, a.force)?;
    info!("bundle: {}", bundle.display());

    // Sign bundle
    if let Some(ref cert) = cert_source {
        let ts = if a.timestamp_url.is_empty() {
            None
        } else {
            Some(a.timestamp_url.as_str())
        };
        sign_artifact(
            &tools,
            &SignOptions {
                artifact: &bundle,
                certificate: cert.clone(),
                sip_dll: a.sip_dll.as_deref(),
                timestamp_url: ts,
                rfc3161: a.timestamp_mode.eq_ignore_ascii_case("rfc3161"),
                signtool_override: a.signtool_path.as_deref(),
            },
        )?;
        if a.verify {
            verify_signature(&tools, &bundle)?;
        }
    }

    if a.validate {
        validate_package(&tools, &bundle)?;
    }

    println!("✅ {}", bundle.display());
    Ok(())
}
