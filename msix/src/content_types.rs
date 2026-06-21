//! `[Content_Types].xml` generation + extension → MIME table.
//!
//! Mirrors `ContentType.cpp` (extension table + footprint-file content types)
//! and `ContentTypeWriter.cpp` (Default/Override emission rules) from
//! microsoft/msix-packaging.
//!
//! Rules from `ContentTypeWriter::AddContentType`:
//! - If `force_override`: always emit `<Override PartName="/<file>" ContentType=...>`.
//! - Else if file has an extension:
//!   - First time we see the extension → record + emit `<Default>`.
//!   - Same extension, same content-type → no-op.
//!   - Same extension, different content-type → emit `<Override>` for this file.
//! - Else (no extension) → emit `<Override>` for this file.

use quick_xml::Writer;
use quick_xml::events::{BytesDecl, BytesEnd, BytesStart, Event};
use std::collections::HashMap;
use std::io::Cursor;

const NS: &str = "http://schemas.openxmlformats.org/package/2006/content-types";

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Compression {
    None,
    Normal,
}

/// Default content type + compression hint for unknown extensions.
pub const DEFAULT: (&str, Compression) = ("application/octet-stream", Compression::Normal);

/// Footprint-file content types (mirror `GetPayloadFileContentType`).
pub const MANIFEST_CT: &str = "application/vnd.ms-appx.manifest+xml";
pub const BLOCKMAP_CT: &str = "application/vnd.ms-appx.blockmap+xml";
pub const SIGNATURE_CT: &str = "application/vnd.ms-appx.signature";

/// Resolve an extension (lowercase, no leading dot) to (content-type, compression).
/// Mirrors `ContentType::GetContentTypeByExtension` table from MS SDK.
pub fn by_extension(ext: &str) -> (&'static str, Compression) {
    use Compression::*;
    match ext {
        "atom" => ("application/atom+xml", Normal),
        "appx" | "msix" => ("application/vnd.ms-appx", None),
        "b64" => ("application/base64", Normal),
        "cab" => ("application/vnd.ms-cab-compressed", None),
        "doc" | "dot" => ("application/msword", Normal),
        "docm" | "dotm" => ("application/vnd.ms-word.document.macroenabled.12", None),
        "docx" | "dotx" => (
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            None,
        ),
        "dll" | "exe" => ("application/x-msdownload", Normal),
        "dtd" => ("application/xml-dtd", Normal),
        "gz" => ("application/x-gzip-compressed", None),
        "java" => ("application/java", Normal),
        "json" => ("application/json", Normal),
        "p7s" => ("application/x-pkcs7-signature", Normal),
        "pdf" => ("application/pdf", Normal),
        "ps" => ("application/postscript", Normal),
        "potm" => (
            "application/vnd.ms-powerpoint.template.macroenabled.12",
            None,
        ),
        "potx" => (
            "application/vnd.openxmlformats-officedocument.presentationml.template",
            None,
        ),
        "ppam" => ("application/vnd.ms-powerpoint.addin.macroenabled.12", None),
        "ppsm" => (
            "application/vnd.ms-powerpoint.slideshow.macroenabled.12",
            None,
        ),
        "ppsx" => (
            "application/vnd.openxmlformats-officedocument.presentationml.slideshow",
            None,
        ),
        "ppt" | "pot" | "pps" | "ppa" => ("application/vnd.ms-powerpoint", Normal),
        "pptm" => (
            "application/vnd.ms-powerpoint.presentation.macroenabled.12",
            None,
        ),
        "pptx" => (
            "application/vnd.openxmlformats-officedocument.presentationml.presentation",
            None,
        ),
        "rar" => ("application/x-rar-compressed", None),
        "rss" => ("application/rss+xml", Normal),
        "soap" => ("application/soap+xml", Normal),
        "tar" => ("application/x-tar", None),
        "xaml" => ("application/xaml+xml", Normal),
        "xap" => ("application/x-silverlight-app", None),
        "xbap" => ("application/x-ms-xbap", Normal),
        "xhtml" => ("application/xhtml+xml", Normal),
        "xlam" => ("application/vnd.ms-excel.addin.macroenabled.12", None),
        "xls" | "xlt" | "xla" => ("application/vnd.ms-excel", Normal),
        "xlsb" => (
            "application/vnd.ms-excel.sheet.binary.macroEnabled.12",
            None,
        ),
        "xlsm" => ("application/vnd.ms-excel.sheet.macroEnabled.12", None),
        "xlsx" => (
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            None,
        ),
        "xltm" => ("application/vnd.ms-excel.template.macroEnabled.12", None),
        "xltx" => (
            "application/vnd.openxmlformats-officedocument.spreadsheetml.template",
            None,
        ),
        "xsl" | "xslt" => ("application/xslt+xml", Normal),
        "zip" => ("application/x-zip-compressed", None),
        // text
        "c" | "cpp" | "cs" | "h" | "txt" => ("text/plain", Normal),
        "css" => ("text/css", Normal),
        "csv" => ("text/csv", Normal),
        "htm" | "html" => ("text/html", Normal),
        "js" => ("application/x-javascript", Normal),
        "rtf" => ("text/richtext", Normal),
        "sct" => ("text/scriptlet", Normal),
        "xml" | "xsd" => ("text/xml", Normal),
        // audio
        "aiff" => ("audio/x-aiff", Normal),
        "au" => ("audio/basic", Normal),
        "m4a" => ("audio/mp4", None),
        "mid" | "smf" => ("audio/mid", Normal),
        "mp3" => ("audio/mpeg", None),
        "wav" => ("audio/wav", Normal),
        "wma" => ("audio/x-ms-wma", None),
        // image
        "bmp" => ("image/bmp", Normal),
        "emf" => ("image/x-emf", Normal),
        "gif" => ("image/gif", None),
        "ico" => ("image/vnd.microsoft.icon", Normal),
        "jpg" | "jpeg" => ("image/jpeg", None),
        "png" => ("image/png", None),
        "svg" => ("image/svg+xml", Normal),
        "tif" | "tiff" => ("image/tiff", Normal),
        "wmf" => ("image/x-wmf", Normal),
        // video
        "avi" => ("video/avi", None),
        "mpeg" | "mpg" => ("video/mpeg", None),
        "mov" => ("video/quicktime", None),
        "wmv" => ("video/x-ms-wmv", None),
        _ => DEFAULT,
    }
}

pub struct ContentTypeWriter {
    xml: Writer<Cursor<Vec<u8>>>,
    /// Extension (lowercase) → content-type recorded via `<Default>`.
    defaults: HashMap<String, String>,
}

impl ContentTypeWriter {
    pub fn new() -> quick_xml::Result<Self> {
        let mut xml = Writer::new(Cursor::new(Vec::with_capacity(2048)));
        xml.write_event(Event::Decl(BytesDecl::new("1.0", Some("UTF-8"), None)))?;
        let mut root = BytesStart::new("Types");
        root.push_attribute(("xmlns", NS));
        xml.write_event(Event::Start(root))?;
        Ok(Self {
            xml,
            defaults: HashMap::new(),
        })
    }

    pub fn add_content_type(
        &mut self,
        name: &str,
        content_type: &str,
        force_override: bool,
    ) -> quick_xml::Result<()> {
        if force_override {
            return self.add_override(name, content_type);
        }
        match name.rsplit_once('.') {
            Some((_, ext)) if !ext.is_empty() => {
                let normalized = ext.to_ascii_lowercase();
                match self.defaults.get(&normalized) {
                    Some(existing) if existing == content_type => Ok(()),
                    Some(_) => self.add_override(name, content_type),
                    None => {
                        self.defaults.insert(normalized, content_type.to_string());
                        self.add_default(ext, content_type)
                    }
                }
            }
            _ => self.add_override(name, content_type),
        }
    }

    fn add_default(&mut self, ext: &str, content_type: &str) -> quick_xml::Result<()> {
        let mut el = BytesStart::new("Default");
        el.push_attribute(("ContentType", content_type));
        el.push_attribute(("Extension", ext));
        self.xml.write_event(Event::Empty(el))
    }

    fn add_override(&mut self, name: &str, content_type: &str) -> quick_xml::Result<()> {
        let part_name = format!("/{name}");
        let mut el = BytesStart::new("Override");
        el.push_attribute(("ContentType", content_type));
        el.push_attribute(("PartName", part_name.as_str()));
        self.xml.write_event(Event::Empty(el))
    }

    pub fn finish(mut self) -> quick_xml::Result<Vec<u8>> {
        self.xml.write_event(Event::End(BytesEnd::new("Types")))?;
        Ok(self.xml.into_inner().into_inner())
    }
}
