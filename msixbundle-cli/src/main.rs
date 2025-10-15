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

    /// Sign PFX (if omitted, no signing)
    #[arg(long)]
    pfx: Option<PathBuf>,

    /// PFX password
    #[arg(long)]
    pfx_password: Option<String>,

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

    let mut tools = locate_sdk_tools()?;
    if let Some(p) = &a.signtool_path {
        tools.signtool = Some(p.clone());
    }

    // Pack per-arch
    let mut built: Vec<(String, PathBuf)> = Vec::new();
    let mut info: Option<ManifestInfo> = None;

    if let Some(dir) = &a.dir_x64 {
        let m = read_manifest_info(dir)?;
        info = Some(m.clone());
        info!("x64: {}", dir.display());
        let msix = pack_arch(&tools, dir, &a.out_dir, &m, "x64")?;
        built.push(("x64".into(), msix));
    }

    if let Some(dir) = &a.dir_arm64 {
        let m = read_manifest_info(dir)?;
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
        let msix = pack_arch(&tools, dir, &a.out_dir, &m, "arm64")?;
        built.push(("arm64".into(), msix));
    }

    let info = info.expect("manifest info");
    if a.validate {
        for (_, p) in &built {
            validate_package(&tools, p)?;
        }
    }

    // Sign per-arch (optional, often skipped)
    if a.sign_each {
        if let (Some(pfx), Some(pass)) = (&a.pfx, &a.pfx_password) {
            for (_, msix) in &built {
                sign_artifact(
                    &tools,
                    &SignOptions {
                        artifact: msix,
                        pfx,
                        password: Some(pass),
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
            warn!("--sign-each set but no --pfx/--pfx-password; skipping per-arch signing");
        }
    }

    // Bundle
    let bundle = build_bundle(&tools, &a.out_dir, &built, &info)?;
    info!("bundle: {}", bundle.display());

    // Sign bundle
    if let (Some(pfx), Some(pass)) = (&a.pfx, &a.pfx_password) {
        let ts = if a.timestamp_url.is_empty() {
            None
        } else {
            Some(a.timestamp_url.as_str())
        };
        sign_artifact(
            &tools,
            &SignOptions {
                artifact: &bundle,
                pfx,
                password: Some(pass),
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
