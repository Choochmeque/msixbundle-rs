//! End-to-end signing smoke test: pack a minimal source dir, sign it with a
//! freshly-generated RSA self-signed certificate, and verify the resulting
//! .msix contains a syntactically-valid `AppxSignature.p7x` (PKCX magic +
//! parseable CMS ContentInfo).

use std::io::Read;

use msix::{PackOptions, RsaSigner, pack, sign_package};

const MANIFEST_XML: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10">
  <Identity Name="Test.App" Publisher="CN=Test" Version="1.0.0.0" ProcessorArchitecture="x64"/>
  <Properties><DisplayName>Test</DisplayName><PublisherDisplayName>Test</PublisherDisplayName><Logo>l.png</Logo></Properties>
  <Resources><Resource Language="en-us"/></Resources>
</Package>
"#;

// A pre-generated 2048-bit RSA key + self-signed cert (CN=Test, valid for
// 10 years from 2025). Inline rather than generating at test time so we
// don't need rcgen / openssl as a dev-dep.
const TEST_PEM: &str = include_str!("fixtures/test_sign.pem");

#[test]
fn sign_minimal_package() {
    let src = tempfile::tempdir().expect("create temp source dir");
    let out = tempfile::NamedTempFile::new().expect("create temp output");

    std::fs::write(src.path().join("AppxManifest.xml"), MANIFEST_XML).expect("write manifest");
    std::fs::write(src.path().join("hello.txt"), b"hello msix signed\n").expect("write payload");

    pack(src.path(), out.path(), &PackOptions::default()).expect("pack");

    let signer = RsaSigner::from_pem(TEST_PEM).expect("parse PEM bundle");
    sign_package(out.path(), &signer).expect("sign");

    // Inspect the resulting zip: AppxSignature.p7x must exist and start with PKCX.
    let f = std::fs::File::open(out.path()).expect("open signed package");
    let mut zip = zip::ZipArchive::new(f).expect("parse signed package as zip");
    let names: Vec<String> = zip.file_names().map(String::from).collect();
    assert!(
        names.contains(&"AppxSignature.p7x".to_string()),
        "missing AppxSignature.p7x: {names:?}"
    );

    let mut p7x = Vec::new();
    zip.by_name("AppxSignature.p7x")
        .expect("AppxSignature.p7x entry")
        .read_to_end(&mut p7x)
        .expect("read p7x");
    // PKCX magic = 0x504b4358 (big-endian "PKCX").
    assert_eq!(&p7x[..4], b"PKCX", "wrong p7x magic, got {:?}", &p7x[..4]);

    // The rest should parse as a CMS ContentInfo whose content-type is
    // pkcs7-signedData (1.2.840.113549.1.7.2).
    let info: rasn_cms::ContentInfo = rasn::der::decode(&p7x[4..]).expect("decode ContentInfo");
    assert_eq!(
        &*info.content_type,
        rasn_cms::CONTENT_SIGNED_DATA,
        "p7x is not a pkcs7-signedData ContentInfo"
    );

    // The package's existing entries are still readable.
    for entry in [
        "AppxManifest.xml",
        "AppxBlockMap.xml",
        "[Content_Types].xml",
        "hello.txt",
    ] {
        assert!(
            names.contains(&entry.to_string()),
            "missing {entry} in {names:?}"
        );
    }

    // [Content_Types].xml must declare the signature override (pack pre-emits it).
    let mut ct = String::new();
    zip.by_name("[Content_Types].xml")
        .expect("[Content_Types].xml")
        .read_to_string(&mut ct)
        .expect("read content types");
    assert!(
        ct.contains(r#"PartName="/AppxSignature.p7x""#),
        "content types missing signature override: {ct}"
    );
}
