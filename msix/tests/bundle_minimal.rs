//! Bundle smoke test: create two stub packages, bundle them, verify the
//! resulting .msixbundle is a readable zip with the expected layout and
//! that the bundle manifest's Offset/Size attributes point at the actual
//! byte ranges of the contained files.

use std::io::Read;

use msix::{Architecture, BundleIdentity, ContainedPackage, PackOptions, bundle, pack};

const MANIFEST_X64: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10">
  <Identity Name="Test.App" Publisher="CN=Test" Version="1.0.0.0" ProcessorArchitecture="x64"/>
  <Properties><DisplayName>T</DisplayName><PublisherDisplayName>T</PublisherDisplayName><Logo>l.png</Logo></Properties>
</Package>
"#;

const MANIFEST_ARM64: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10">
  <Identity Name="Test.App" Publisher="CN=Test" Version="1.0.0.0" ProcessorArchitecture="arm64"/>
  <Properties><DisplayName>T</DisplayName><PublisherDisplayName>T</PublisherDisplayName><Logo>l.png</Logo></Properties>
</Package>
"#;

fn make_msix(manifest: &str) -> (tempfile::TempDir, tempfile::NamedTempFile) {
    let src = tempfile::tempdir().expect("create temp source dir");
    let out = tempfile::NamedTempFile::new().expect("create temp output file");
    std::fs::write(src.path().join("AppxManifest.xml"), manifest).expect("write manifest");
    std::fs::write(src.path().join("payload.txt"), b"hi\n").expect("write payload");
    pack(src.path(), out.path(), &PackOptions::default()).expect("pack succeeds");
    (src, out)
}

#[test]
fn bundle_two_archs() {
    let (_src_x64, x64_msix) = make_msix(MANIFEST_X64);
    let (_src_arm64, arm64_msix) = make_msix(MANIFEST_ARM64);
    let bundle_out = tempfile::NamedTempFile::new().expect("create temp bundle output");

    let packages = vec![
        ContainedPackage {
            path: x64_msix.path().to_path_buf(),
            filename: "Test.App_1.0.0.0_x64.msix".to_string(),
            architecture: Architecture::X64,
            version: "1.0.0.0".to_string(),
            resources: vec![],
        },
        ContainedPackage {
            path: arm64_msix.path().to_path_buf(),
            filename: "Test.App_1.0.0.0_arm64.msix".to_string(),
            architecture: Architecture::Arm64,
            version: "1.0.0.0".to_string(),
            resources: vec![],
        },
    ];
    let identity = BundleIdentity {
        name: "Test.App".to_string(),
        publisher: "CN=Test".to_string(),
        version: "1.0.0.0".to_string(),
    };

    bundle(&packages, bundle_out.path(), &identity).expect("bundle succeeds");

    // Read the bundle back.
    let f = std::fs::File::open(bundle_out.path()).expect("open bundle output");
    let mut zip = zip::ZipArchive::new(f).expect("parse bundle as zip");
    let names: Vec<String> = zip.file_names().map(String::from).collect();

    for must_have in [
        "Test.App_1.0.0.0_x64.msix",
        "Test.App_1.0.0.0_arm64.msix",
        "AppxMetadata/AppxBundleManifest.xml",
        "AppxBlockMap.xml",
        "[Content_Types].xml",
    ] {
        assert!(
            names.contains(&must_have.to_string()),
            "missing {must_have} in {names:?}"
        );
    }

    // Manifest mentions both architectures.
    let mut m = String::new();
    zip.by_name("AppxMetadata/AppxBundleManifest.xml")
        .expect("AppxBundleManifest.xml entry")
        .read_to_string(&mut m)
        .expect("read bundle manifest as utf-8");
    assert!(m.contains(r#"Architecture="x64""#), "manifest = {m}");
    assert!(m.contains(r#"Architecture="arm64""#), "manifest = {m}");
    assert!(m.contains(r#"Name="Test.App""#), "manifest = {m}");

    // Bundle BlockMap covers ONLY the bundle manifest, not the contained packages.
    let mut bm = String::new();
    zip.by_name("AppxBlockMap.xml")
        .expect("AppxBlockMap.xml entry")
        .read_to_string(&mut bm)
        .expect("read bundle blockmap as utf-8");
    assert!(
        bm.contains(r#"Name="AppxMetadata\AppxBundleManifest.xml""#),
        "bundle blockmap missing manifest entry: {bm}"
    );
    assert!(
        !bm.contains(".msix\""),
        "bundle blockmap should not include contained packages: {bm}"
    );

    // Content types: appx/msix Default + bundlemanifest+xml + blockmap override.
    let mut ct = String::new();
    zip.by_name("[Content_Types].xml")
        .expect("[Content_Types].xml entry")
        .read_to_string(&mut ct)
        .expect("read content types as utf-8");
    assert!(ct.contains(r#"Extension="msix""#), "ct = {ct}");
    assert!(
        ct.contains("application/vnd.ms-appx.bundlemanifest+xml"),
        "ct = {ct}"
    );
    assert!(ct.contains(r#"PartName="/AppxBlockMap.xml""#), "ct = {ct}");

    // Cross-check: parse Offset/Size from manifest and verify those bytes match
    // the contained .msix file as read by the zip crate.
    let off_x64 = parse_attr(&m, "FileName=\"Test.App_1.0.0.0_x64.msix\"", "Offset");
    let size_x64 = parse_attr(&m, "FileName=\"Test.App_1.0.0.0_x64.msix\"", "Size");
    let expected_x64_bytes = std::fs::read(x64_msix.path()).expect("read original x64 msix");
    let actual_bundle_bytes = std::fs::read(bundle_out.path()).expect("read bundle output");
    assert_eq!(
        size_x64 as usize,
        expected_x64_bytes.len(),
        "Size attr wrong"
    );
    let slice = &actual_bundle_bytes[off_x64 as usize..off_x64 as usize + size_x64 as usize];
    assert_eq!(
        slice,
        expected_x64_bytes.as_slice(),
        "Offset slice != original msix"
    );
}

/// Pulls a u64 attribute value from the `<Package FileName=... Attr="value" ...>` element
/// matched by `tag` (a `FileName="..."` substring used to locate the row).
fn parse_attr(manifest: &str, tag: &str, attr: &str) -> u64 {
    let row_start = manifest.find(tag).expect("tag not found in manifest");
    let row_end = manifest[row_start..].find("/>").expect("row end") + row_start;
    let row = &manifest[row_start..row_end];
    let needle = format!("{attr}=\"");
    let v_start = row.find(&needle).expect("attr not found") + needle.len();
    let v_end = row[v_start..].find('"').expect("attr value end") + v_start;
    row[v_start..v_end]
        .parse()
        .expect("manifest attribute should parse as u64")
}
