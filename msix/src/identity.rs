//! Read package identity from an existing `.msix` / `.appx` on disk.
//!
//! Mirrors what `MakeAppx.exe bundle` does implicitly — opens the package,
//! parses `AppxManifest.xml`, and reports the `<Identity ...>` attributes.
//! `build_bundle` callers need this to construct `AppxBundleManifest.xml`.

use std::fs::File;
use std::io::Read;
use std::path::Path;

use quick_xml::events::Event;
use quick_xml::Reader;

use crate::bundle::Architecture;
use crate::{MsixError, Result};

#[derive(Clone, Debug)]
pub struct PackageIdentity {
    pub name: String,
    pub publisher: String,
    pub version: String,
    pub architecture: Architecture,
}

/// Open `path` as a zip, read `AppxManifest.xml`, parse the `<Identity ...>`
/// element, and return it.
pub fn read_identity(path: &Path) -> Result<PackageIdentity> {
    let f = File::open(path)?;
    let mut zip = zip::ZipArchive::new(f).map_err(zip_to_msix)?;
    let mut entry = zip
        .by_name("AppxManifest.xml")
        .map_err(|_| MsixError::ManifestMissing(path.to_path_buf()))?;
    let mut xml = String::new();
    entry.read_to_string(&mut xml)?;

    parse_identity(&xml)
}

fn parse_identity(xml: &str) -> Result<PackageIdentity> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    let mut buf = Vec::new();
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) | Ok(Event::Empty(e)) if e.name().as_ref() == b"Identity" => {
                let mut name = None;
                let mut publisher = None;
                let mut version = None;
                let mut arch = None;
                for attr in e.attributes().flatten() {
                    let v = attr
                        .decode_and_unescape_value(reader.decoder())
                        .map_err(MsixError::Xml)?
                        .into_owned();
                    match attr.key.as_ref() {
                        b"Name" => name = Some(v),
                        b"Publisher" => publisher = Some(v),
                        b"Version" => version = Some(v),
                        b"ProcessorArchitecture" => arch = Some(v),
                        _ => {}
                    }
                }
                return Ok(PackageIdentity {
                    name: name.ok_or(MsixError::ManifestField("Identity@Name"))?,
                    publisher: publisher.ok_or(MsixError::ManifestField("Identity@Publisher"))?,
                    version: version.ok_or(MsixError::ManifestField("Identity@Version"))?,
                    architecture: arch
                        .as_deref()
                        .map(parse_architecture)
                        .transpose()?
                        .unwrap_or(Architecture::Neutral),
                });
            }
            Ok(Event::Eof) => return Err(MsixError::ManifestField("Identity element not found")),
            Ok(_) => {}
            Err(e) => return Err(MsixError::Xml(e)),
        }
        buf.clear();
    }
}

fn parse_architecture(s: &str) -> Result<Architecture> {
    Ok(match s.to_ascii_lowercase().as_str() {
        "neutral" | "" => Architecture::Neutral,
        "x86" => Architecture::X86,
        "x64" => Architecture::X64,
        "arm" => Architecture::Arm,
        "arm64" => Architecture::Arm64,
        _ => return Err(MsixError::UnknownArchitecture(s.to_string())),
    })
}

fn zip_to_msix(e: zip::result::ZipError) -> MsixError {
    MsixError::Io(std::io::Error::other(e.to_string()))
}
