//! End-to-end smoke test: pack a minimal source dir and verify the output
//! is a readable zip with the expected three footprint entries plus payload.

use std::fs;
use std::io::Read;

use msix::{pack, PackOptions};

const MANIFEST_XML: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10">
  <Identity Name="Test.App" Publisher="CN=Test" Version="1.0.0.0" ProcessorArchitecture="x64"/>
  <Properties>
    <DisplayName>Test</DisplayName>
    <PublisherDisplayName>Test</PublisherDisplayName>
    <Logo>Assets\Logo.png</Logo>
  </Properties>
</Package>
"#;

#[test]
fn pack_minimal_dir() {
    let src = tempfile::tempdir().unwrap();
    let out = tempfile::NamedTempFile::new().unwrap();

    // source layout:
    //   AppxManifest.xml
    //   hello.txt
    //   Assets/Logo.png   (tiny stub)
    fs::write(src.path().join("AppxManifest.xml"), MANIFEST_XML).unwrap();
    fs::write(src.path().join("hello.txt"), b"hello msix\n").unwrap();
    fs::create_dir(src.path().join("Assets")).unwrap();
    fs::write(src.path().join("Assets/Logo.png"), b"\x89PNG\r\n\x1a\n").unwrap();

    pack(src.path(), out.path(), &PackOptions::default()).unwrap();

    // Re-open as a zip and check structure.
    let f = fs::File::open(out.path()).unwrap();
    let mut zip = zip::ZipArchive::new(f).unwrap();
    let names: Vec<String> = zip.file_names().map(String::from).collect();

    assert!(names.contains(&"AppxManifest.xml".to_string()), "names = {names:?}");
    assert!(names.contains(&"AppxBlockMap.xml".to_string()), "names = {names:?}");
    assert!(names.contains(&"[Content_Types].xml".to_string()), "names = {names:?}");
    assert!(names.contains(&"hello.txt".to_string()), "names = {names:?}");
    assert!(names.contains(&"Assets/Logo.png".to_string()), "names = {names:?}");

    // Manifest content roundtrips byte-for-byte.
    let mut s = String::new();
    zip.by_name("AppxManifest.xml").unwrap().read_to_string(&mut s).unwrap();
    assert_eq!(s, MANIFEST_XML);

    // BlockMap mentions our payload with backslash separator.
    let mut bm = String::new();
    zip.by_name("AppxBlockMap.xml").unwrap().read_to_string(&mut bm).unwrap();
    assert!(bm.contains(r#"Name="Assets\Logo.png""#), "blockmap = {bm}");
    assert!(bm.contains(r#"Name="hello.txt""#), "blockmap = {bm}");
    assert!(bm.contains("HashMethod=\"http://www.w3.org/2001/04/xmlenc#sha256\""));
    // hello.txt is text/plain → Normal → DEFLATE → blocks carry a Size= attr.
    // PNG is image/png → None → STORED → blocks have no Size= attr.
    let hello_blocks = blocks_inside(&bm, "hello.txt");
    assert!(
        hello_blocks.iter().all(|b| b.contains("Size=\"")),
        "compressed entry should carry Block Size=; blocks = {hello_blocks:?}; bm = {bm}"
    );
    let png_blocks = blocks_inside(&bm, r"Assets\Logo.png");
    assert!(
        png_blocks.iter().all(|b| !b.contains("Size=\"")),
        "stored entry should not carry Block Size=; blocks = {png_blocks:?}; bm = {bm}"
    );

    // Content types has Default for txt and png, Override for the blockmap + manifest.
    let mut ct = String::new();
    zip.by_name("[Content_Types].xml").unwrap().read_to_string(&mut ct).unwrap();
    assert!(ct.contains(r#"Extension="txt""#), "ct = {ct}");
    assert!(ct.contains(r#"Extension="png""#), "ct = {ct}");
    assert!(ct.contains(r#"PartName="/AppxBlockMap.xml""#), "ct = {ct}");
    assert!(ct.contains(r#"PartName="/AppxManifest.xml""#), "ct = {ct}");
}

/// Collect every `<Block .../>` substring that appears inside the `<File>`
/// element for `name`. Strips the opening `<File ...>` tag so its `Size=`
/// attribute doesn't pollute the check.
fn blocks_inside<'a>(bm: &'a str, name: &str) -> Vec<&'a str> {
    let needle = format!(r#"Name="{name}""#);
    let name_at = bm.find(&needle).expect("name not found in blockmap");
    let body_start = bm[name_at..].find('>').expect("malformed File open") + name_at + 1;
    let body_end = bm[body_start..].find("</File>").expect("no </File>") + body_start;
    let body = &bm[body_start..body_end];
    let mut out = Vec::new();
    let mut rest = body;
    while let Some(start) = rest.find("<Block") {
        let after = &rest[start..];
        let end = after.find("/>").expect("self-closing Block expected") + 2;
        out.push(&after[..end]);
        rest = &after[end..];
    }
    out
}
