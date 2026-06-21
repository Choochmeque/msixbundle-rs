//! `.msixbundle` creation.
//!
//! No MS open-source reference exists for bundle *creation* — the SDK only
//! contains unpack code; `MakeAppx.exe bundle` is closed-source. Structure
//! reverse-engineered from a known-good bundle (`testData/unpack/bundles/
//! MainBundle.appxbundle`):
//!
//! - Contained packages (`.msix` / `.appx`) at root, **STORED** (already
//!   internally compressed).
//! - `AppxMetadata/AppxBundleManifest.xml` — Identity + per-package
//!   `<Package Architecture=... FileName=... Offset=... Size=...>` rows.
//!   `Offset` is the byte position of the contained file's *data* (just
//!   past the LFH), `Size` is its byte length.
//! - `AppxBlockMap.xml` — covers **only the bundle manifest**, not the
//!   contained packages.
//! - `[Content_Types].xml` — Defaults for `appx`/`msix` and `xml`
//!   (mapped to bundlemanifest+xml, not the regular manifest+xml).
//!
//! Out of scope for this first cut: `<Resources>` (Language/Scale qualifiers),
//! optional packages, resource packs, signing. Single-bundle-of-N-packages
//! covers the common multi-arch case.

use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

use quick_xml::events::{BytesDecl, BytesEnd, BytesStart, Event};
use quick_xml::Writer;

use crate::block_map::{BlockMapWriter, BLOCK_SIZE};
use crate::content_types::{self, ContentTypeWriter};
use crate::zip_writer::ZipWriter;
use crate::Result;

const BUNDLE_NS: &str = "http://schemas.microsoft.com/appx/2013/bundle";
const SCHEMA_VERSION: &str = "3.0";
const BUNDLE_MANIFEST_PATH: &str = "AppxMetadata/AppxBundleManifest.xml";
const BLOCKMAP_PATH: &str = "AppxBlockMap.xml";
const CONTENT_TYPES_PATH: &str = "[Content_Types].xml";
const BUNDLEMANIFEST_CT: &str = "application/vnd.ms-appx.bundlemanifest+xml";

/// Bundle-level identity (distinct from each contained package's identity).
pub struct BundleIdentity {
    pub name: String,
    pub publisher: String,
    /// Quad-dotted version, e.g. `"1.0.0.0"`.
    pub version: String,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Architecture {
    Neutral,
    X86,
    X64,
    Arm,
    Arm64,
}

impl Architecture {
    fn as_str(self) -> &'static str {
        match self {
            Self::Neutral => "neutral",
            Self::X86 => "x86",
            Self::X64 => "x64",
            Self::Arm => "arm",
            Self::Arm64 => "arm64",
        }
    }
}

pub struct ContainedPackage {
    /// Path to the `.msix` / `.appx` file on disk.
    pub path: PathBuf,
    /// File name to use inside the bundle zip.
    pub filename: String,
    pub architecture: Architecture,
    /// Quad-dotted version of the *contained* package.
    pub version: String,
}

pub fn bundle(packages: &[ContainedPackage], output: &Path, identity: &BundleIdentity) -> Result<()> {
    if packages.is_empty() {
        return Err(crate::MsixError::EmptyBundle);
    }

    let out = BufWriter::new(File::create(output)?);
    let mut zip = ZipWriter::new(out);
    let mut block_map = BlockMapWriter::new()?;
    let mut content_types = ContentTypeWriter::new()?;

    // 1) Pack contained .msix files (STORED), recording (offset, size).
    let mut records = Vec::with_capacity(packages.len());
    for pkg in packages {
        content_types.add_content_type(&pkg.filename, content_types::by_extension("msix").0, false)?;
        let bytes = std::fs::read(&pkg.path)?;
        zip.start_file(&pkg.filename, false)?;
        let data_offset = zip.position()?;
        for chunk in bytes.chunks(BLOCK_SIZE) {
            zip.write_block(chunk)?;
        }
        zip.end_file()?;
        records.push(PackageRecord {
            filename: pkg.filename.clone(),
            architecture: pkg.architecture,
            version: pkg.version.clone(),
            offset: data_offset,
            size: bytes.len() as u64,
        });
    }

    // 2) Emit the bundle manifest XML (in memory).
    let manifest_bytes = build_bundle_manifest(identity, &records)?;

    // 3) Add the bundle manifest as a DEFLATE entry tracked in the bundle blockmap.
    content_types.add_content_type(BUNDLE_MANIFEST_PATH, BUNDLEMANIFEST_CT, false)?;
    let lfh = zip.start_file(BUNDLE_MANIFEST_PATH, true)?;
    block_map.start_file(BUNDLE_MANIFEST_PATH, manifest_bytes.len() as u64, lfh)?;
    for chunk in manifest_bytes.chunks(BLOCK_SIZE) {
        let written = zip.write_block(chunk)?;
        block_map.add_block(chunk, Some(written))?;
    }
    zip.end_file()?;
    block_map.end_file()?;

    // 4) Close and write the bundle's blockmap.
    let block_map_bytes = block_map.finish()?;
    content_types.add_content_type(BLOCKMAP_PATH, content_types::BLOCKMAP_CT, true)?;
    zip.start_file(BLOCKMAP_PATH, true)?;
    for chunk in block_map_bytes.chunks(BLOCK_SIZE) {
        zip.write_block(chunk)?;
    }
    zip.end_file()?;

    // 5) Content types last.
    let content_types_bytes = content_types.finish()?;
    zip.start_file(CONTENT_TYPES_PATH, true)?;
    for chunk in content_types_bytes.chunks(BLOCK_SIZE) {
        zip.write_block(chunk)?;
    }
    zip.end_file()?;

    let mut writer = zip.finish()?;
    writer.flush()?;
    Ok(())
}

struct PackageRecord {
    filename: String,
    architecture: Architecture,
    version: String,
    offset: u64,
    size: u64,
}

fn build_bundle_manifest(identity: &BundleIdentity, records: &[PackageRecord]) -> Result<Vec<u8>> {
    let mut xml = Writer::new(std::io::Cursor::new(Vec::with_capacity(2048)));
    xml.write_event(Event::Decl(BytesDecl::new("1.0", Some("UTF-8"), Some("no"))))?;

    let mut bundle_el = BytesStart::new("Bundle");
    bundle_el.push_attribute(("xmlns", BUNDLE_NS));
    bundle_el.push_attribute(("SchemaVersion", SCHEMA_VERSION));
    xml.write_event(Event::Start(bundle_el))?;

    let mut id = BytesStart::new("Identity");
    id.push_attribute(("Name", identity.name.as_str()));
    id.push_attribute(("Publisher", identity.publisher.as_str()));
    id.push_attribute(("Version", identity.version.as_str()));
    xml.write_event(Event::Empty(id))?;

    xml.write_event(Event::Start(BytesStart::new("Packages")))?;
    for r in records {
        let offset = r.offset.to_string();
        let size = r.size.to_string();
        let mut p = BytesStart::new("Package");
        p.push_attribute(("Type", "application"));
        p.push_attribute(("Version", r.version.as_str()));
        p.push_attribute(("Architecture", r.architecture.as_str()));
        p.push_attribute(("FileName", r.filename.as_str()));
        p.push_attribute(("Offset", offset.as_str()));
        p.push_attribute(("Size", size.as_str()));
        xml.write_event(Event::Start(p))?;
        // <Resources> is required by the bundle schema; WACK fails to parse
        // packages without it. We emit a minimum (language = en-us) until we
        // wire through per-package resource extraction.
        xml.write_event(Event::Start(BytesStart::new("Resources")))?;
        let mut res = BytesStart::new("Resource");
        res.push_attribute(("Language", "en-us"));
        xml.write_event(Event::Empty(res))?;
        xml.write_event(Event::End(BytesEnd::new("Resources")))?;
        xml.write_event(Event::End(BytesEnd::new("Package")))?;
    }
    xml.write_event(Event::End(BytesEnd::new("Packages")))?;
    xml.write_event(Event::End(BytesEnd::new("Bundle")))?;
    Ok(xml.into_inner().into_inner())
}
