#![cfg(all(target_os = "windows", feature = "sdk-discovery"))]

use msixbundle::*;
use std::path::Path;
use tempfile::tempdir;

fn create_minimal_appx_content(dir: &Path) {
    let manifest = r#"<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"
         xmlns:uap="http://schemas.microsoft.com/appx/manifest/uap/windows10"
         xmlns:rescap="http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities">
  <Identity Name="TestCompany.TestApp" Version="1.0.0.0"
            Publisher="CN=Test" ProcessorArchitecture="x64"/>
  <Properties>
    <DisplayName>TestApp</DisplayName>
    <PublisherDisplayName>Test Company</PublisherDisplayName>
    <Logo>Assets\logo.png</Logo>
  </Properties>
  <Resources>
    <Resource Language="en-us"/>
  </Resources>
  <Dependencies>
    <TargetDeviceFamily Name="Windows.Desktop" MinVersion="10.0.17763.0" MaxVersionTested="10.0.22621.0"/>
  </Dependencies>
  <Capabilities>
    <rescap:Capability Name="runFullTrust"/>
  </Capabilities>
  <Applications>
    <Application Id="App" Executable="app.exe" EntryPoint="Windows.FullTrustApplication">
      <uap:VisualElements DisplayName="TestApp" Description="Test"
                          Square150x150Logo="Assets\logo.png" Square44x44Logo="Assets\logo.png"
                          BackgroundColor="transparent"/>
    </Application>
  </Applications>
</Package>"#;

    std::fs::write(dir.join("AppxManifest.xml"), manifest).expect("write manifest");
    std::fs::create_dir_all(dir.join("Assets")).expect("create Assets dir");
    // Create minimal PNG (1x1 transparent)
    let png = include_bytes!("fixtures/logo.png");
    std::fs::write(dir.join("Assets").join("logo.png"), png).expect("write logo");
    // Create dummy exe
    std::fs::write(dir.join("app.exe"), b"MZ").expect("write exe");
}

#[test]
fn test_locate_sdk_tools() {
    let tools = locate_sdk_tools().expect("SDK should be installed");
    assert!(tools.makeappx.exists());
}

#[test]
fn test_pack_arch() {
    let tools = locate_sdk_tools().expect("locate SDK");
    let content_dir = tempdir().expect("create content dir");
    let out_dir = tempdir().expect("create out dir");

    create_minimal_appx_content(content_dir.path());
    let info = read_manifest_info(content_dir.path()).expect("read manifest");

    let msix = pack_arch(
        &tools,
        content_dir.path(),
        out_dir.path(),
        &info,
        "x64",
        false,
    )
    .expect("pack");
    assert!(msix.exists());
    assert!(msix.to_string_lossy().ends_with(".msix"));

    // Validate by unpacking - if MakeAppx can unpack it, the package is valid
    let unpack_dir = tempdir().expect("create unpack dir");
    let status = std::process::Command::new(&tools.makeappx)
        .args([
            "unpack",
            "/p",
            &msix.to_string_lossy(),
            "/d",
            &unpack_dir.path().to_string_lossy(),
            "/o", // overwrite
        ])
        .status()
        .expect("run unpack");
    assert!(
        status.success(),
        "MakeAppx unpack should succeed for valid package"
    );

    // Verify expected files exist after unpack
    assert!(unpack_dir.path().join("AppxManifest.xml").exists());
    assert!(unpack_dir.path().join("AppxBlockMap.xml").exists());

    // Verify AppxManifest.xml is valid and contains expected data
    let manifest_content =
        std::fs::read_to_string(unpack_dir.path().join("AppxManifest.xml")).expect("read manifest");
    assert!(
        manifest_content.contains("<Package"),
        "should have Package element"
    );
    assert!(
        manifest_content.contains("TestCompany.TestApp"),
        "should have Identity Name"
    );
    assert!(manifest_content.contains("1.0.0.0"), "should have Version");

    // Verify AppxBlockMap.xml is valid XML
    let blockmap_content =
        std::fs::read_to_string(unpack_dir.path().join("AppxBlockMap.xml")).expect("read blockmap");
    assert!(
        blockmap_content.contains("<BlockMap"),
        "should have BlockMap element"
    );

    // Verify assets were included
    assert!(unpack_dir.path().join("Assets").join("logo.png").exists());
    assert!(unpack_dir.path().join("app.exe").exists());
}

#[test]
fn test_build_bundle() {
    let tools = locate_sdk_tools().expect("locate SDK");
    let content_dir = tempdir().expect("create content dir");
    let out_dir = tempdir().expect("create out dir");

    create_minimal_appx_content(content_dir.path());
    let info = read_manifest_info(content_dir.path()).expect("read manifest");

    let msix = pack_arch(
        &tools,
        content_dir.path(),
        out_dir.path(),
        &info,
        "x64",
        false,
    )
    .expect("pack");
    let built = vec![("x64".to_string(), msix)];

    let bundle = build_bundle(&tools, out_dir.path(), &built, &info, false).expect("build bundle");
    assert!(bundle.exists());
    assert!(bundle.to_string_lossy().ends_with(".msixbundle"));

    // Validate by unbundling - if MakeAppx can unbundle it, the bundle is valid
    let unbundle_dir = tempdir().expect("create unbundle dir");
    let status = std::process::Command::new(&tools.makeappx)
        .args([
            "unbundle",
            "/p",
            &bundle.to_string_lossy(),
            "/d",
            &unbundle_dir.path().to_string_lossy(),
            "/o", // overwrite
        ])
        .status()
        .expect("run unbundle");
    assert!(
        status.success(),
        "MakeAppx unbundle should succeed for valid bundle"
    );

    // Verify AppxBundleManifest.xml exists and is valid
    assert!(unbundle_dir
        .path()
        .join("AppxMetadata")
        .join("AppxBundleManifest.xml")
        .exists());
    let bundle_manifest = std::fs::read_to_string(
        unbundle_dir
            .path()
            .join("AppxMetadata")
            .join("AppxBundleManifest.xml"),
    )
    .expect("read bundle manifest");
    assert!(
        bundle_manifest.contains("<Bundle"),
        "should have Bundle element"
    );
    assert!(
        bundle_manifest.contains("TestApp"),
        "should reference the app"
    );

    // Verify the bundle contains expected MSIX files
    let msix_files: Vec<_> = std::fs::read_dir(unbundle_dir.path())
        .expect("read unbundle dir")
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path()
                .extension()
                .map(|ext| ext == "msix")
                .unwrap_or(false)
        })
        .collect();
    assert!(
        !msix_files.is_empty(),
        "Bundle should contain at least one .msix"
    );

    // Verify extracted MSIX filename matches expected pattern
    let msix_name = msix_files[0].file_name();
    let msix_name_str = msix_name.to_string_lossy();
    assert!(
        msix_name_str.contains("TestApp"),
        "MSIX filename should contain app name"
    );
    assert!(
        msix_name_str.contains("1.0.0.0"),
        "MSIX filename should contain version"
    );
}

fn create_appx_content_for_arch(dir: &Path, arch: &str) {
    let manifest = format!(
        r#"<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"
         xmlns:uap="http://schemas.microsoft.com/appx/manifest/uap/windows10"
         xmlns:rescap="http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities">
  <Identity Name="TestCompany.TestApp" Version="1.0.0.0"
            Publisher="CN=Test" ProcessorArchitecture="{arch}"/>
  <Properties>
    <DisplayName>TestApp</DisplayName>
    <PublisherDisplayName>Test Company</PublisherDisplayName>
    <Logo>Assets\logo.png</Logo>
  </Properties>
  <Resources>
    <Resource Language="en-us"/>
  </Resources>
  <Dependencies>
    <TargetDeviceFamily Name="Windows.Desktop" MinVersion="10.0.17763.0" MaxVersionTested="10.0.22621.0"/>
  </Dependencies>
  <Capabilities>
    <rescap:Capability Name="runFullTrust"/>
  </Capabilities>
  <Applications>
    <Application Id="App" Executable="app.exe" EntryPoint="Windows.FullTrustApplication">
      <uap:VisualElements DisplayName="TestApp" Description="Test"
                          Square150x150Logo="Assets\logo.png" Square44x44Logo="Assets\logo.png"
                          BackgroundColor="transparent"/>
    </Application>
  </Applications>
</Package>"#
    );

    std::fs::write(dir.join("AppxManifest.xml"), manifest).expect("write manifest");
    std::fs::create_dir_all(dir.join("Assets")).expect("create Assets dir");
    let png = include_bytes!("fixtures/logo.png");
    std::fs::write(dir.join("Assets").join("logo.png"), png).expect("write logo");
    std::fs::write(dir.join("app.exe"), b"MZ").expect("write exe");
}

#[test]
fn test_multi_arch_bundle() {
    let tools = locate_sdk_tools().expect("locate SDK");
    let x64_dir = tempdir().expect("create x64 dir");
    let arm64_dir = tempdir().expect("create arm64 dir");
    let out_dir = tempdir().expect("create out dir");

    // Create content for both architectures
    create_appx_content_for_arch(x64_dir.path(), "x64");
    create_appx_content_for_arch(arm64_dir.path(), "arm64");

    let info = read_manifest_info(x64_dir.path()).expect("read manifest");

    // Pack both architectures
    let msix_x64 =
        pack_arch(&tools, x64_dir.path(), out_dir.path(), &info, "x64", false).expect("pack x64");
    let msix_arm64 = pack_arch(
        &tools,
        arm64_dir.path(),
        out_dir.path(),
        &info,
        "arm64",
        false,
    )
    .expect("pack arm64");

    let built = vec![
        ("x64".to_string(), msix_x64),
        ("arm64".to_string(), msix_arm64),
    ];

    // Build bundle with both architectures
    let bundle = build_bundle(&tools, out_dir.path(), &built, &info, false).expect("build bundle");
    assert!(bundle.exists());

    // Validate by unbundling
    let unbundle_dir = tempdir().expect("create unbundle dir");
    let status = std::process::Command::new(&tools.makeappx)
        .args([
            "unbundle",
            "/p",
            &bundle.to_string_lossy(),
            "/d",
            &unbundle_dir.path().to_string_lossy(),
            "/o",
        ])
        .status()
        .expect("run unbundle");
    assert!(
        status.success(),
        "MakeAppx unbundle should succeed for multi-arch bundle"
    );

    // Verify bundle contains both MSIX files
    let msix_files: Vec<_> = std::fs::read_dir(unbundle_dir.path())
        .expect("read unbundle dir")
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path()
                .extension()
                .map(|ext| ext == "msix")
                .unwrap_or(false)
        })
        .collect();
    assert_eq!(msix_files.len(), 2, "Bundle should contain two .msix files");

    // Verify bundle manifest references both architectures
    let bundle_manifest = std::fs::read_to_string(
        unbundle_dir
            .path()
            .join("AppxMetadata")
            .join("AppxBundleManifest.xml"),
    )
    .expect("read bundle manifest");
    assert!(
        bundle_manifest.contains("x64") || bundle_manifest.contains("X64"),
        "should reference x64"
    );
    assert!(
        bundle_manifest.contains("arm64") || bundle_manifest.contains("Arm64"),
        "should reference arm64"
    );
}

#[test]
fn test_bundlemap_format() {
    let tools = locate_sdk_tools().expect("locate SDK");
    let content_dir = tempdir().expect("create content dir");
    let out_dir = tempdir().expect("create out dir");

    create_minimal_appx_content(content_dir.path());
    let info = read_manifest_info(content_dir.path()).expect("read manifest");

    let msix = pack_arch(
        &tools,
        content_dir.path(),
        out_dir.path(),
        &info,
        "x64",
        false,
    )
    .expect("pack");
    let built = vec![("x64".to_string(), msix.clone())];

    let _bundle = build_bundle(&tools, out_dir.path(), &built, &info, false).expect("build bundle");

    // Read and verify bundlemap.txt format
    let bundlemap_path = out_dir.path().join("bundlemap.txt");
    assert!(bundlemap_path.exists(), "bundlemap.txt should exist");

    let bundlemap_content = std::fs::read_to_string(&bundlemap_path).expect("read bundlemap");

    // Verify format: [Files] header
    assert!(
        bundlemap_content.starts_with("[Files]"),
        "bundlemap should start with [Files]"
    );

    // Verify format: quoted paths with filename as destination
    let msix_filename = msix.file_name().expect("msix filename");
    assert!(
        bundlemap_content.contains(&format!("\"{}\"", msix_filename.to_string_lossy())),
        "bundlemap should contain quoted destination filename"
    );
}

#[test]
fn test_read_manifest_missing_file() {
    let dir = tempdir().expect("create temp dir");
    // Don't create AppxManifest.xml
    let result = read_manifest_info(dir.path());
    assert!(result.is_err(), "should fail when manifest is missing");
}

#[test]
fn test_read_manifest_invalid_xml() {
    let dir = tempdir().expect("create temp dir");
    std::fs::write(dir.path().join("AppxManifest.xml"), "not valid xml <><>").expect("write");
    let result = read_manifest_info(dir.path());
    assert!(result.is_err(), "should fail for invalid XML");
}

#[test]
fn test_read_manifest_missing_identity() {
    let dir = tempdir().expect("create temp dir");
    let manifest = r#"<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10">
  <Properties>
    <DisplayName>TestApp</DisplayName>
  </Properties>
</Package>"#;
    std::fs::write(dir.path().join("AppxManifest.xml"), manifest).expect("write");
    let result = read_manifest_info(dir.path());
    assert!(
        result.is_err(),
        "should fail when Identity element is missing"
    );
}

#[test]
fn test_read_manifest_missing_version() {
    let dir = tempdir().expect("create temp dir");
    let manifest = r#"<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10">
  <Identity Name="TestCompany.TestApp" Publisher="CN=Test"/>
  <Properties>
    <DisplayName>TestApp</DisplayName>
  </Properties>
</Package>"#;
    std::fs::write(dir.path().join("AppxManifest.xml"), manifest).expect("write");
    let result = read_manifest_info(dir.path());
    assert!(
        result.is_err(),
        "should fail when Version attribute is missing"
    );
}

#[test]
fn test_validate_msix_and_bundle() {
    // WACK (appcert.exe) can only run one instance at a time,
    // so we test all validation in a single test.
    let tools = locate_sdk_tools().expect("locate SDK");
    assert!(tools.appcert.is_some(), "WACK not installed");

    let x64_dir = tempdir().expect("create x64 dir");
    let arm64_dir = tempdir().expect("create arm64 dir");
    let out_dir = tempdir().expect("create out dir");

    // Create content for both architectures
    create_appx_content_for_arch(x64_dir.path(), "x64");
    create_appx_content_for_arch(arm64_dir.path(), "arm64");

    let info = read_manifest_info(x64_dir.path()).expect("read manifest");

    // Pack both architectures
    let msix_x64 =
        pack_arch(&tools, x64_dir.path(), out_dir.path(), &info, "x64", false).expect("pack x64");
    let msix_arm64 = pack_arch(
        &tools,
        arm64_dir.path(),
        out_dir.path(),
        &info,
        "arm64",
        false,
    )
    .expect("pack arm64");

    // Validate single MSIX
    validate_package(&tools, &msix_x64).expect("validate x64 msix should pass");

    // Build and validate multi-arch bundle
    let built = vec![
        ("x64".to_string(), msix_x64),
        ("arm64".to_string(), msix_arm64),
    ];
    let bundle = build_bundle(&tools, out_dir.path(), &built, &info, false).expect("build bundle");

    validate_package(&tools, &bundle).expect("validate multi-arch bundle should pass");
}

#[test]
fn test_pack_arch_overwrite_false_fails_when_exists() {
    let tools = locate_sdk_tools().expect("locate SDK");
    let content_dir = tempdir().expect("create content dir");
    let out_dir = tempdir().expect("create out dir");

    create_minimal_appx_content(content_dir.path());
    let info = read_manifest_info(content_dir.path()).expect("read manifest");

    // First pack should succeed
    let msix = pack_arch(
        &tools,
        content_dir.path(),
        out_dir.path(),
        &info,
        "x64",
        false,
    )
    .expect("first pack");
    assert!(msix.exists());

    // Second pack without overwrite should fail
    let result = pack_arch(
        &tools,
        content_dir.path(),
        out_dir.path(),
        &info,
        "x64",
        false,
    );
    assert!(
        result.is_err(),
        "pack should fail when file exists and overwrite=false"
    );
}

#[test]
fn test_pack_arch_overwrite_true_succeeds_when_exists() {
    let tools = locate_sdk_tools().expect("locate SDK");
    let content_dir = tempdir().expect("create content dir");
    let out_dir = tempdir().expect("create out dir");

    create_minimal_appx_content(content_dir.path());
    let info = read_manifest_info(content_dir.path()).expect("read manifest");

    // First pack
    let msix1 = pack_arch(
        &tools,
        content_dir.path(),
        out_dir.path(),
        &info,
        "x64",
        false,
    )
    .expect("first pack");
    assert!(msix1.exists());

    // Second pack with overwrite should succeed
    let msix2 = pack_arch(
        &tools,
        content_dir.path(),
        out_dir.path(),
        &info,
        "x64",
        true,
    )
    .expect("second pack with overwrite");
    assert!(msix2.exists());
    assert_eq!(msix1, msix2, "should produce same path");
}

#[test]
fn test_build_bundle_overwrite_false_fails_when_exists() {
    let tools = locate_sdk_tools().expect("locate SDK");
    let content_dir = tempdir().expect("create content dir");
    let out_dir = tempdir().expect("create out dir");

    create_minimal_appx_content(content_dir.path());
    let info = read_manifest_info(content_dir.path()).expect("read manifest");

    let msix = pack_arch(
        &tools,
        content_dir.path(),
        out_dir.path(),
        &info,
        "x64",
        false,
    )
    .expect("pack");
    let built = vec![("x64".to_string(), msix)];

    // First bundle should succeed
    let bundle = build_bundle(&tools, out_dir.path(), &built, &info, false).expect("first bundle");
    assert!(bundle.exists());

    // Second bundle without overwrite should fail
    let result = build_bundle(&tools, out_dir.path(), &built, &info, false);
    assert!(
        result.is_err(),
        "bundle should fail when file exists and overwrite=false"
    );
}

#[test]
fn test_build_bundle_overwrite_true_succeeds_when_exists() {
    let tools = locate_sdk_tools().expect("locate SDK");
    let content_dir = tempdir().expect("create content dir");
    let out_dir = tempdir().expect("create out dir");

    create_minimal_appx_content(content_dir.path());
    let info = read_manifest_info(content_dir.path()).expect("read manifest");

    let msix = pack_arch(
        &tools,
        content_dir.path(),
        out_dir.path(),
        &info,
        "x64",
        false,
    )
    .expect("pack");
    let built = vec![("x64".to_string(), msix)];

    // First bundle
    let bundle1 = build_bundle(&tools, out_dir.path(), &built, &info, false).expect("first bundle");
    assert!(bundle1.exists());

    // Second bundle with overwrite should succeed
    let bundle2 = build_bundle(&tools, out_dir.path(), &built, &info, true)
        .expect("second bundle with overwrite");
    assert!(bundle2.exists());
    assert_eq!(bundle1, bundle2, "should produce same path");
}

fn setup_test_certificate(dir: &Path) -> (std::path::PathBuf, std::path::PathBuf) {
    let pfx_path = dir.join("APPX_TEST_ROOT.pfx");
    let cer_path = dir.join("APPX_TEST_ROOT.cer");

    let status = std::process::Command::new("powershell")
        .args([
            "-Command",
            r#"
            $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject "CN=MSIX Test Root" -KeyUsage DigitalSignature -CertStoreLocation "Cert:\CurrentUser\My" -NotAfter (Get-Date).AddYears(1)
            Export-PfxCertificate -Cert $cert -FilePath $args[0] -Password (ConvertTo-SecureString -String "test" -Force -AsPlainText)
            Export-Certificate -Cert $cert -FilePath $args[1]
            "#,
        ])
        .arg(&pfx_path)
        .arg(&cer_path)
        .status()
        .expect("Failed to run PowerShell");

    assert!(status.success(), "Failed to generate test certificate");
    assert!(pfx_path.exists(), "PFX file should exist");
    assert!(cer_path.exists(), "CER file should exist");

    (pfx_path, cer_path)
}

#[test]
fn test_sign_and_verify() {
    let tools = locate_sdk_tools().expect("locate SDK");
    let temp = tempdir().expect("create temp dir");

    // 1. Generate test certificate
    let (pfx_path, cer_path) = setup_test_certificate(temp.path());

    // 2. Add certificate to root store (GitHub Actions runs as admin)
    let add_status = std::process::Command::new("certutil")
        .args(["-addstore", "root"])
        .arg(&cer_path)
        .status()
        .expect("Failed to run certutil");
    assert!(add_status.success(), "Failed to add cert to root store");

    // 3. Create and pack a test MSIX
    let content_dir = temp.path().join("content");
    std::fs::create_dir_all(&content_dir).expect("create content dir");
    create_minimal_appx_content(&content_dir);
    let info = read_manifest_info(&content_dir).expect("read manifest");

    let msix_path = pack_arch(&tools, &content_dir, temp.path(), &info, "x64", true).expect("pack");

    // 4. Sign with PFX
    let sign_opts = SignOptions {
        artifact: &msix_path,
        certificate: CertificateSource::Pfx {
            path: &pfx_path,
            password: Some("test"),
        },
        sip_dll: None,
        timestamp_url: None,
        rfc3161: false,
        signtool_override: None,
    };
    sign_artifact(&tools, &sign_opts).expect("sign artifact");

    // 5. Verify signature
    verify_signature(&tools, &msix_path).expect("verify signature");

    // 6. Cleanup: remove cert from root store
    let _ = std::process::Command::new("certutil")
        .args(["-delstore", "root", "MSIX Test Root"])
        .status();
}
