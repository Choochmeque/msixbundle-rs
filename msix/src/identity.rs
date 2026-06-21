//! Read package identity (and resource qualifiers) from an existing
//! `.msix` / `.appx` on disk.
//!
//! Mirrors what `MakeAppx.exe bundle` does implicitly — opens the package,
//! parses `AppxManifest.xml`, and reports `<Identity ...>` plus the list of
//! `<Resources><Resource ...></Resources>` qualifiers. `build_bundle` callers
//! need both to construct `AppxBundleManifest.xml`.

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
    /// Each `<Resource ...>` from the inner manifest, preserving every attribute
    /// in source order (`Language`, `Scale`, `DXFeatureLevel`, `MinVersion`, ...).
    pub resources: Vec<Resource>,
}

/// One `<Resource ...>` element from `<Resources>`. Stored as
/// `(attribute name, attribute value)` pairs to forward unknown qualifiers
/// untouched into the bundle manifest.
#[derive(Clone, Debug, Default)]
pub struct Resource {
    pub attributes: Vec<(String, String)>,
}

/// Open `path` as a zip, read `AppxManifest.xml`, parse `<Identity>` and
/// `<Resources>`.
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

    let mut name: Option<String> = None;
    let mut publisher: Option<String> = None;
    let mut version: Option<String> = None;
    let mut arch: Option<String> = None;
    let mut resources: Vec<Resource> = Vec::new();
    let mut in_resources = false;

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) | Ok(Event::Empty(e)) => match e.name().as_ref() {
                b"Identity" if name.is_none() => {
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
                }
                b"Resources" => in_resources = true,
                b"Resource" if in_resources => {
                    let mut attrs = Vec::new();
                    for attr in e.attributes().flatten() {
                        let key = std::str::from_utf8(attr.key.as_ref())
                            .map_err(|_| MsixError::ManifestField("Resource attr name not utf-8"))?
                            .to_string();
                        let value = attr
                            .decode_and_unescape_value(reader.decoder())
                            .map_err(MsixError::Xml)?
                            .into_owned();
                        attrs.push((key, value));
                    }
                    resources.push(Resource { attributes: attrs });
                }
                _ => {}
            },
            Ok(Event::End(e)) if e.name().as_ref() == b"Resources" => {
                in_resources = false;
            }
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(e) => return Err(MsixError::Xml(e)),
        }
        buf.clear();
    }

    Ok(PackageIdentity {
        name: name.ok_or(MsixError::ManifestField("Identity@Name"))?,
        publisher: publisher.ok_or(MsixError::ManifestField("Identity@Publisher"))?,
        version: version.ok_or(MsixError::ManifestField("Identity@Version"))?,
        architecture: arch
            .as_deref()
            .map(parse_architecture)
            .transpose()?
            .unwrap_or(Architecture::Neutral),
        resources,
    })
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
