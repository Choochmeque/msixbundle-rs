//! End-to-end smoke for the cross-platform `NativeBackend` of `msixbundle`:
//! pack two per-arch directories, bundle the resulting `.msix` files,
//! verify the bundle is a readable zip containing both packages + a
//! bundle manifest whose `<Identity>` was extracted from the first package.

#![cfg(feature = "native")]

use std::fs;
use std::io::Read;

use msixbundle::{MsixBackend, NativeBackend};

const MANIFEST_X64: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10">
  <Identity Name="Test.NativeBackend" Publisher="CN=NativeBackendTest" Version="2.0.0.0" ProcessorArchitecture="x64"/>
  <Properties><DisplayName>T</DisplayName><PublisherDisplayName>T</PublisherDisplayName><Logo>l.png</Logo></Properties>
</Package>
"#;

const MANIFEST_ARM64: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10">
  <Identity Name="Test.NativeBackend" Publisher="CN=NativeBackendTest" Version="2.0.0.0" ProcessorArchitecture="arm64"/>
  <Properties><DisplayName>T</DisplayName><PublisherDisplayName>T</PublisherDisplayName><Logo>l.png</Logo></Properties>
</Package>
"#;

fn make_src(manifest: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("create temp source dir");
    fs::write(dir.path().join("AppxManifest.xml"), manifest).expect("write manifest");
    fs::write(dir.path().join("payload.txt"), b"hi\n").expect("write payload");
    dir
}

#[test]
fn native_backend_pack_then_bundle() {
    let backend = NativeBackend;

    let src_x64 = make_src(MANIFEST_X64);
    let src_arm64 = make_src(MANIFEST_ARM64);
    let msix_x64 = tempfile::NamedTempFile::new().expect("temp x64 msix");
    let msix_arm64 = tempfile::NamedTempFile::new().expect("temp arm64 msix");
    let bundle_path = tempfile::NamedTempFile::new().expect("temp bundle");

    backend
        .pack(src_x64.path(), msix_x64.path())
        .expect("pack x64");
    backend
        .pack(src_arm64.path(), msix_arm64.path())
        .expect("pack arm64");

    let packages = vec![
        ("x64".to_string(), msix_x64.path().to_path_buf()),
        ("arm64".to_string(), msix_arm64.path().to_path_buf()),
    ];
    backend
        .bundle(&packages, bundle_path.path())
        .expect("bundle");

    let f = fs::File::open(bundle_path.path()).expect("open bundle");
    let mut zip = zip::ZipArchive::new(f).expect("parse bundle as zip");
    let names: Vec<String> = zip.file_names().map(String::from).collect();
    for must in [
        "AppxMetadata/AppxBundleManifest.xml",
        "AppxBlockMap.xml",
        "[Content_Types].xml",
    ] {
        assert!(names.contains(&must.to_string()), "missing {must} in {names:?}");
    }

    let mut bm = String::new();
    zip.by_name("AppxMetadata/AppxBundleManifest.xml")
        .expect("AppxBundleManifest.xml entry")
        .read_to_string(&mut bm)
        .expect("read bundle manifest as utf-8");
    // Identity was extracted from the first package's AppxManifest.xml.
    assert!(bm.contains(r#"Name="Test.NativeBackend""#), "manifest = {bm}");
    assert!(bm.contains(r#"Publisher="CN=NativeBackendTest""#), "manifest = {bm}");
    assert!(bm.contains(r#"Version="2.0.0.0""#), "manifest = {bm}");
    assert!(bm.contains(r#"Architecture="x64""#), "manifest = {bm}");
    assert!(bm.contains(r#"Architecture="arm64""#), "manifest = {bm}");
}
