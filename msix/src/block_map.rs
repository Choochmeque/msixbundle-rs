//! `AppxBlockMap.xml` generation.
//!
//! Mirrors `AppxBlockMapWriter.cpp` from microsoft/msix-packaging. Each payload
//! file is split into 64 KiB blocks; each block contributes a SHA-256 hash
//! (base64-encoded). For DEFLATE-compressed entries, each block also records its
//! compressed size (`Size` attribute); for STORED entries, `Size` is omitted —
//! matching the MS implementation's `AppxBlockMapWriter::AddBlock`.
//!
//! Output shape:
//! ```xml
//! <BlockMap HashMethod="http://www.w3.org/2001/04/xmlenc#sha256"
//!           xmlns="http://schemas.microsoft.com/appx/2010/blockmap">
//!   <File Name="App1.exe" Size="18944" LfhSize="38">
//!     <Block Hash="ORIk+3QF9mSpuOq51oT3Xqn0Gy0vcGbnBRn5lBg5irM="/>
//!   </File>
//! </BlockMap>
//! ```

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use quick_xml::events::{BytesDecl, BytesEnd, BytesStart, Event};
use quick_xml::Writer;
use sha2::{Digest, Sha256};
use std::io::Cursor;

pub const BLOCK_SIZE: usize = 64 * 1024;

const NS: &str = "http://schemas.microsoft.com/appx/2010/blockmap";
const HASH_METHOD: &str = "http://www.w3.org/2001/04/xmlenc#sha256";

pub struct BlockMapWriter {
    xml: Writer<Cursor<Vec<u8>>>,
}

impl BlockMapWriter {
    pub fn new() -> quick_xml::Result<Self> {
        let mut xml = Writer::new(Cursor::new(Vec::with_capacity(4096)));
        xml.write_event(Event::Decl(BytesDecl::new("1.0", Some("UTF-8"), None)))?;
        let mut root = BytesStart::new("BlockMap");
        root.push_attribute(("xmlns", NS));
        root.push_attribute(("HashMethod", HASH_METHOD));
        xml.write_event(Event::Start(root))?;
        Ok(Self { xml })
    }

    /// Begin a `<File>` entry. `name` uses forward slashes here; converted to
    /// backslashes for the `Name=` attribute per the MS implementation.
    pub fn start_file(
        &mut self,
        name: &str,
        uncompressed_size: u64,
        lfh_size: u32,
    ) -> quick_xml::Result<()> {
        let win_name = name.replace('/', "\\");
        let size = uncompressed_size.to_string();
        let lfh = lfh_size.to_string();
        let mut el = BytesStart::new("File");
        el.push_attribute(("Name", win_name.as_str()));
        el.push_attribute(("Size", size.as_str()));
        el.push_attribute(("LfhSize", lfh.as_str()));
        self.xml.write_event(Event::Start(el))
    }

    /// Append a `<Block>` element. `compressed_size = None` for STORED entries.
    pub fn add_block(&mut self, raw_block: &[u8], compressed_size: Option<u32>) -> quick_xml::Result<()> {
        let mut hasher = Sha256::new();
        hasher.update(raw_block);
        let hash = B64.encode(hasher.finalize());

        let mut el = BytesStart::new("Block");
        el.push_attribute(("Hash", hash.as_str()));
        let size_str;
        if let Some(s) = compressed_size {
            size_str = s.to_string();
            el.push_attribute(("Size", size_str.as_str()));
        }
        self.xml.write_event(Event::Empty(el))
    }

    pub fn end_file(&mut self) -> quick_xml::Result<()> {
        self.xml.write_event(Event::End(BytesEnd::new("File")))
    }

    pub fn finish(mut self) -> quick_xml::Result<Vec<u8>> {
        self.xml.write_event(Event::End(BytesEnd::new("BlockMap")))?;
        Ok(self.xml.into_inner().into_inner())
    }
}
