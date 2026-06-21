//! Top-level pack orchestrator.
//!
//! Mirrors `AppxPackageWriter.cpp` + `PackPackage` (`msix.cpp`) from
//! microsoft/msix-packaging. Phase 1 scope:
//!
//! - DEFLATE compression on for entries the content_types table flags as
//!   `Compression::Normal`; STORED for `Compression::None`.
//! - Walks the source dir in sorted-by-name order. The MS impl sorts by
//!   last-mod date; sorted-by-name is determinism-friendly.
//! - Footprint files at the root (`AppxManifest.xml`, `AppxBlockMap.xml`,
//!   `[Content_Types].xml`, `AppxSignature.p7x`, `AppxMetadata/`) are
//!   excluded from payload.
//! - File-name percent-encoding (`Encoding::EncodeFileName`) is deferred —
//!   only safe for ASCII paths without reserved chars.

use std::fs::File;
use std::io::{BufWriter, Read};
use std::path::Path;

use walkdir::WalkDir;

use crate::block_map::{BLOCK_SIZE, BlockMapWriter};
use crate::content_types::{self, Compression, ContentTypeWriter};
use crate::zip_writer::ZipWriter;
use crate::{MsixError, Result};

const FOOTPRINT_MANIFEST: &str = "AppxManifest.xml";
const FOOTPRINT_BLOCKMAP: &str = "AppxBlockMap.xml";
const FOOTPRINT_CONTENT_TYPES: &str = "[Content_Types].xml";
const FOOTPRINT_SIGNATURE: &str = "AppxSignature.p7x";
const RESERVED_DIR: &str = "AppxMetadata";

#[derive(Debug, Clone, Default)]
pub struct PackOptions {
    // Placeholder for future flags (compression level, force overwrite, etc.).
}

/// Pack `source_dir` into an MSIX file at `output`. Expects an `AppxManifest.xml`
/// at the root of `source_dir`.
pub fn pack(source_dir: &Path, output: &Path, _opts: &PackOptions) -> Result<()> {
    let manifest_path = source_dir.join(FOOTPRINT_MANIFEST);
    if !manifest_path.exists() {
        return Err(MsixError::ManifestMissing(manifest_path));
    }

    let payload = collect_payload(source_dir)?;

    let out = BufWriter::new(File::create(output)?);
    let mut zip = ZipWriter::new(out);
    let mut block_map = BlockMapWriter::new()?;
    let mut content_types = ContentTypeWriter::new()?;

    for entry in &payload {
        write_payload(&mut zip, &mut block_map, &mut content_types, entry)?;
    }

    // Manifest (always compressed per MS — manifest is text/xml).
    let manifest_bytes = std::fs::read(&manifest_path)?;
    write_footprint(
        &mut zip,
        &mut block_map,
        &mut content_types,
        FOOTPRINT_MANIFEST,
        &manifest_bytes,
        Some(content_types::MANIFEST_CT),
        true,
        true,
    )?;

    // BlockMap — itself compressed, not added to its own blockmap.
    let block_map_bytes = block_map.finish()?;
    let _ = write_zip_entry(&mut zip, FOOTPRINT_BLOCKMAP, &block_map_bytes, true)?;
    content_types.add_content_type(FOOTPRINT_BLOCKMAP, content_types::BLOCKMAP_CT, true)?;
    // Pre-declare the signature override so [Content_Types].xml is stable across
    // signing — `sign_package` only appends the AppxSignature.p7x entry and
    // doesn't have to rewrite content types (which would invalidate AXCT).
    content_types.add_content_type(FOOTPRINT_SIGNATURE, content_types::SIGNATURE_CT, true)?;

    // [Content_Types].xml — generated last, no entry in itself, no entry in blockmap.
    let content_types_bytes = content_types.finish()?;
    let _ = write_zip_entry(
        &mut zip,
        FOOTPRINT_CONTENT_TYPES,
        &content_types_bytes,
        true,
    )?;

    zip.finish()?;
    Ok(())
}

struct PayloadEntry {
    /// Path relative to source_dir, using forward slashes.
    rel_name: String,
    /// Absolute path on disk.
    abs_path: std::path::PathBuf,
}

fn collect_payload(source_dir: &Path) -> Result<Vec<PayloadEntry>> {
    let mut out = Vec::new();
    for dent in WalkDir::new(source_dir).sort_by_file_name() {
        let dent = dent.map_err(|e| std::io::Error::other(e.to_string()))?;
        if !dent.file_type().is_file() {
            continue;
        }
        let rel = dent
            .path()
            .strip_prefix(source_dir)
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        let rel_name = rel
            .components()
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join("/");
        if is_footprint(&rel_name) {
            continue;
        }
        out.push(PayloadEntry {
            rel_name,
            abs_path: dent.path().to_path_buf(),
        });
    }
    Ok(out)
}

fn is_footprint(name: &str) -> bool {
    matches!(
        name,
        FOOTPRINT_MANIFEST | FOOTPRINT_BLOCKMAP | FOOTPRINT_CONTENT_TYPES | FOOTPRINT_SIGNATURE
    ) || name.starts_with(&format!("{RESERVED_DIR}/"))
}

fn write_payload<W: std::io::Write + std::io::Seek>(
    zip: &mut ZipWriter<W>,
    block_map: &mut BlockMapWriter,
    content_types: &mut ContentTypeWriter,
    entry: &PayloadEntry,
) -> Result<()> {
    let ext = extension(&entry.rel_name).unwrap_or_default();
    let (ct, compression) = content_types::by_extension(&ext);
    content_types.add_content_type(&entry.rel_name, ct, false)?;

    let compress = matches!(compression, Compression::Normal);
    let mut f = File::open(&entry.abs_path)?;
    let uncompressed_size = f.metadata()?.len();

    let lfh = zip.start_file(&entry.rel_name, compress)?;
    block_map.start_file(&entry.rel_name, uncompressed_size, lfh)?;

    let mut buf = vec![0u8; BLOCK_SIZE];
    loop {
        let n = read_full(&mut f, &mut buf)?;
        if n == 0 {
            break;
        }
        let compressed_bytes = zip.write_block(&buf[..n])?;
        let size_for_block = compress.then_some(compressed_bytes);
        block_map.add_block(&buf[..n], size_for_block)?;
        if n < BLOCK_SIZE {
            break;
        }
    }
    zip.end_file()?;
    block_map.end_file()?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn write_footprint<W: std::io::Write + std::io::Seek>(
    zip: &mut ZipWriter<W>,
    block_map: &mut BlockMapWriter,
    content_types: &mut ContentTypeWriter,
    name: &str,
    bytes: &[u8],
    content_type: Option<&str>,
    add_to_blockmap: bool,
    compress: bool,
) -> Result<()> {
    if let Some(ct) = content_type {
        content_types.add_content_type(name, ct, true)?;
    }

    let lfh = zip.start_file(name, compress)?;
    if add_to_blockmap {
        block_map.start_file(name, bytes.len() as u64, lfh)?;
    }
    for chunk in bytes.chunks(BLOCK_SIZE) {
        let written = zip.write_block(chunk)?;
        if add_to_blockmap {
            let size_for_block = compress.then_some(written);
            block_map.add_block(chunk, size_for_block)?;
        }
    }
    zip.end_file()?;
    if add_to_blockmap {
        block_map.end_file()?;
    }
    Ok(())
}

/// Write a single-shot entry (used for footprint files not in blockmap).
/// Returns the LFH size.
fn write_zip_entry<W: std::io::Write + std::io::Seek>(
    zip: &mut ZipWriter<W>,
    name: &str,
    bytes: &[u8],
    compress: bool,
) -> Result<u32> {
    let lfh = zip.start_file(name, compress)?;
    for chunk in bytes.chunks(BLOCK_SIZE) {
        zip.write_block(chunk)?;
    }
    zip.end_file()?;
    Ok(lfh)
}

fn extension(name: &str) -> Option<String> {
    name.rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase())
}

/// Read up to `buf.len()` bytes into `buf`, handling short reads by retrying.
/// Returns the actual byte count (0 on EOF).
fn read_full<R: Read>(reader: &mut R, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut total = 0;
    while total < buf.len() {
        match reader.read(&mut buf[total..])? {
            0 => break,
            n => total += n,
        }
    }
    Ok(total)
}
