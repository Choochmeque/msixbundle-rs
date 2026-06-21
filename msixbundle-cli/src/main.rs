use anyhow::{Context, Result, bail};
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

    /// Generate resources.pri with MakePri before packing (Windows only)
    #[arg(long)]
    makepri: bool,

    /// Override makepri.exe path
    #[arg(long, requires = "makepri")]
    makepri_path: Option<PathBuf>,

    /// Default resource language for MakePri (for example: en-us)
    #[arg(long, default_value = "en-us", requires = "makepri")]
    makepri_default_language: String,

    /// Target OS version for MakePri /pv (for example: 10.0.0)
    #[arg(long, default_value = "10.0.0", requires = "makepri")]
    makepri_target_os_version: String,

    /// Keep generated priconfig.xml after MakePri
    #[arg(long, requires = "makepri")]
    makepri_keep_config: bool,

    /// Validate packages with appcert after build (Windows only)
    #[arg(long)]
    validate: bool,

    /// Verify signatures with SignTool after signing (Windows only)
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
        unsafe {
            std::env::set_var("RUST_LOG", "info");
        }
    }
    env_logger::init();

    if a.dir_x64.is_none() && a.dir_arm64.is_none() {
        bail!("Provide at least one of --dir-x64 or --dir-arm64");
    }
    std::fs::create_dir_all(&a.out_dir)?;
    let out_dir = resolve_path(&a.out_dir)?;

    let cert_source = build_cert_source(&a);
    // SDK-only operations. `--pfx` is no longer in this list — we handle it
    // natively via msix::RsaSigner / sign_package. `--thumbprint` still needs
    // the Windows cert store; `--validate` / `--verify` / `--makepri` need
    // appcert / SignTool / MakePri.
    let sdk_only_requested = a.makepri || a.validate || a.verify || a.thumbprint.is_some();
    if sdk_only_requested && !cfg!(target_os = "windows") {
        bail!(
            "--makepri / --validate / --verify / --thumbprint require Windows \
             (no native equivalent yet)"
        );
    }

    let native_signer = build_native_signer(&a)?;
    let (backend, sdk_tools) = build_backend(&a)?;

    // Pack per-arch
    let mut built: Vec<(String, PathBuf)> = Vec::new();
    let mut info: Option<ManifestInfo> = None;

    if let Some(dir) = &a.dir_x64 {
        let dir = resolve_path(dir)?;
        let m = read_manifest_info(&dir)?;
        maybe_makepri(sdk_tools.as_ref(), &a, &dir, "x64")?;
        info = Some(m.clone());
        info!("x64: {}", dir.display());
        let msix = backend.pack_arch(&dir, &out_dir, &m, "x64")?;
        built.push(("x64".into(), msix));
    }

    if let Some(dir) = &a.dir_arm64 {
        let dir = resolve_path(dir)?;
        let m = read_manifest_info(&dir)?;
        if let Some(i) = &info {
            if i.version != m.version {
                bail!("Version mismatch: {} vs {}", i.version, m.version);
            }
        } else {
            info = Some(m.clone());
        }
        maybe_makepri(sdk_tools.as_ref(), &a, &dir, "arm64")?;
        info!("arm64: {}", dir.display());
        let msix = backend.pack_arch(&dir, &out_dir, &m, "arm64")?;
        built.push(("arm64".into(), msix));
    }

    let info = info.expect("manifest info");

    if a.validate {
        let tools = sdk_tools.as_ref().expect("validate gated to windows above");
        for (_, p) in &built {
            validate_package(tools, p)?;
        }
    }

    // Sign per-arch (optional, often skipped). Prefer the native signer when
    // we have one (avoids SignTool); fall back to SDK SignTool if a cert was
    // requested via --thumbprint (Windows store, native can't reach it).
    if a.sign_each {
        for (_, msix) in &built {
            sign_one(
                msix,
                native_signer.as_ref(),
                cert_source.as_ref(),
                sdk_tools.as_ref(),
                &a,
                /*timestamp=*/ false,
            )?;
        }
    }

    // Bundle
    let bundle = backend.build_bundle(&out_dir, &built, &info)?;
    info!("bundle: {}", bundle.display());

    // Sign bundle
    sign_one(
        &bundle,
        native_signer.as_ref(),
        cert_source.as_ref(),
        sdk_tools.as_ref(),
        &a,
        /*timestamp=*/ true,
    )?;

    if a.validate {
        let tools = sdk_tools.as_ref().expect("validate gated to windows above");
        validate_package(tools, &bundle)?;
    }

    println!("ok {}", bundle.display());
    Ok(())
}

fn build_cert_source(a: &Args) -> Option<CertificateSource<'_>> {
    if let Some(pfx) = &a.pfx {
        Some(CertificateSource::Pfx {
            path: pfx,
            password: a.pfx_password.as_deref(),
        })
    } else {
        a.thumbprint
            .as_deref()
            .map(|sha1| CertificateSource::Thumbprint {
                sha1,
                store: Some(a.cert_store.as_str()),
                machine_store: a.machine_store,
            })
    }
}

/// Load a `--pfx` into a native [`msix::RsaSigner`] (used when the native
/// backend is active). Returns `None` if no `--pfx` was given, or when the
/// `native` feature is off.
#[cfg(feature = "native")]
fn build_native_signer(a: &Args) -> Result<Option<msix::RsaSigner>> {
    let Some(pfx_path) = a.pfx.as_ref() else {
        return Ok(None);
    };
    let bytes =
        std::fs::read(pfx_path).with_context(|| format!("read PFX {}", pfx_path.display()))?;
    let signer = msix::RsaSigner::from_pfx(&bytes, a.pfx_password.as_deref().unwrap_or(""))
        .with_context(|| format!("parse PFX {}", pfx_path.display()))?;
    Ok(Some(signer))
}

#[cfg(not(feature = "native"))]
fn build_native_signer(_a: &Args) -> Result<Option<()>> {
    Ok(None)
}

/// Sign one artifact (`.msix` or `.msixbundle`). Prefers the native signer
/// (no SignTool); falls back to SDK SignTool when the cert was given via
/// `--thumbprint` (Windows cert store, native can't reach it).
#[allow(clippy::needless_pass_by_value)]
#[allow(unused_variables)]
fn sign_one(
    artifact: &std::path::Path,
    #[cfg(feature = "native")] native_signer: Option<&msix::RsaSigner>,
    #[cfg(not(feature = "native"))] native_signer: Option<&()>,
    cert_source: Option<&CertificateSource<'_>>,
    sdk_tools: Option<&SdkTools>,
    a: &Args,
    timestamp: bool,
) -> Result<()> {
    #[cfg(feature = "native")]
    if let Some(signer) = native_signer {
        msix::sign_package(artifact, signer)
            .with_context(|| format!("native sign {}", artifact.display()))?;
        if a.verify {
            warn!("--verify ignored for native signing (SignTool only)");
        }
        return Ok(());
    }
    // SDK path: SignTool with thumbprint (or PFX when native is off).
    let Some(cert) = cert_source else {
        if a.sign_each || (artifact.extension().and_then(|e| e.to_str()) == Some("msixbundle")) {
            warn!(
                "no --pfx or --thumbprint supplied; skipping signing of {}",
                artifact.display()
            );
        }
        return Ok(());
    };
    let Some(tools) = sdk_tools else {
        bail!("SDK signing requested but SDK tools not available");
    };
    let ts = if timestamp && !a.timestamp_url.is_empty() {
        Some(a.timestamp_url.as_str())
    } else {
        None
    };
    sign_artifact(
        tools,
        &SignOptions {
            artifact,
            certificate: cert.clone(),
            sip_dll: a.sip_dll.as_deref(),
            timestamp_url: ts,
            rfc3161: a.timestamp_mode.eq_ignore_ascii_case("rfc3161"),
            signtool_override: a.signtool_path.as_deref(),
        },
    )?;
    if a.verify {
        verify_signature(tools, artifact)?;
    }
    Ok(())
}

/// Backend selection: if `native` is enabled, use NativeBackend for pack/bundle
/// on every OS (avoids shelling out to MakeAppx). SdkBackend is the fallback
/// for builds with `native` disabled (Windows only). The SDK tools are still
/// located when `sdk-discovery` is on, because sign/validate/verify/makepri
/// always go through SignTool/appcert/MakePri — those have no native impl yet.
#[cfg(feature = "native")]
fn build_backend(a: &Args) -> Result<(Box<dyn MsixBackend>, Option<SdkTools>)> {
    let backend: Box<dyn MsixBackend> = Box::new(NativeBackend);
    let tools = locate_sdk_tools_opt(a)?;
    Ok((backend, tools))
}

#[cfg(all(
    not(feature = "native"),
    target_os = "windows",
    feature = "sdk-discovery"
))]
fn build_backend(a: &Args) -> Result<(Box<dyn MsixBackend>, Option<SdkTools>)> {
    let mut tools = locate_sdk_tools()?;
    if let Some(p) = &a.signtool_path {
        tools.signtool = Some(p.clone());
    }
    if let Some(p) = &a.makepri_path {
        tools.makepri = Some(p.clone());
    }
    let backend: Box<dyn MsixBackend> = Box::new(SdkBackend {
        tools: tools.clone(),
        overwrite: a.force,
    });
    Ok((backend, Some(tools)))
}

#[cfg(not(any(
    feature = "native",
    all(target_os = "windows", feature = "sdk-discovery"),
)))]
fn build_backend(_a: &Args) -> Result<(Box<dyn MsixBackend>, Option<SdkTools>)> {
    bail!("no backend available (enable `native` or, on Windows, `sdk-discovery`)")
}

/// On Windows with sdk-discovery, locate SDK tools (for sign/validate/verify/
/// makepri). Elsewhere, return None — the early `sdk_requested` bail in
/// `main` catches misuse.
#[cfg(all(target_os = "windows", feature = "sdk-discovery"))]
fn locate_sdk_tools_opt(a: &Args) -> Result<Option<SdkTools>> {
    let mut tools = locate_sdk_tools()?;
    if let Some(p) = &a.signtool_path {
        tools.signtool = Some(p.clone());
    }
    if let Some(p) = &a.makepri_path {
        tools.makepri = Some(p.clone());
    }
    Ok(Some(tools))
}

#[cfg(not(all(target_os = "windows", feature = "sdk-discovery")))]
fn locate_sdk_tools_opt(_a: &Args) -> Result<Option<SdkTools>> {
    Ok(None)
}

fn maybe_makepri(
    tools: Option<&SdkTools>,
    a: &Args,
    dir: &std::path::Path,
    arch: &str,
) -> Result<()> {
    if !a.makepri {
        return Ok(());
    }
    let tools = tools.expect("makepri gated to windows above");
    let pri = compile_resources_pri(
        tools,
        &PriOptions {
            appx_content_dir: dir,
            default_language: a.makepri_default_language.as_str(),
            target_os_version: a.makepri_target_os_version.as_str(),
            keep_priconfig: a.makepri_keep_config,
            overwrite: a.force,
            makepri_override: None,
        },
    )?;
    info!("{arch} PRI: {}", pri.display());
    Ok(())
}
