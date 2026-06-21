//! Minimal ZIP writer with per-block DEFLATE control.
//!
//! Mirrors `ZipObjectWriter.cpp` + `DeflateStream.cpp` from
//! microsoft/msix-packaging, scoped to what MSIX pack needs:
//!
//! - Traditional 32-bit ZIP records (no ZIP64) — first cut. Entries and total
//!   archive must each fit in 4 GiB. MS code uses ZIP64 unconditionally; we
//!   defer that until a real >4 GiB case forces it.
//! - One `Compress` per file, raw DEFLATE (`wbits = -15`), best level.
//! - Per-block `FlushCompress::Full` matches MS's `Z_FULL_FLUSH` so each
//!   block in `AppxBlockMap.xml` can be inflated independently.
//! - LFH is written first with size/crc zeroed, then patched in place after
//!   the file body — same as `ZipObjectWriter::EndFile`'s "rewrite LFH"
//!   path. No Data Descriptor.
//! - File names emitted UTF-8 with the GP flag bit 11 set.

use std::io::{Seek, SeekFrom, Write};

use crc32fast::Hasher;
use flate2::{Compress, Compression, FlushCompress, Status};

use crate::{MsixError, Result};

const LFH_SIG: u32 = 0x0403_4b50;
const CDH_SIG: u32 = 0x0201_4b50;
const EOCD_SIG: u32 = 0x0605_4b50;

const VERSION_NEEDED: u16 = 20;
const VERSION_MADE_BY: u16 = (3 << 8) | 63; // Unix host, ZIP 6.3 features.

const GP_FLAG_UTF8: u16 = 1 << 11;

const METHOD_STORED: u16 = 0;
const METHOD_DEFLATE: u16 = 8;

pub struct ZipWriter<W: Write + Seek> {
    inner: W,
    entries: Vec<Entry>,
    cur: Option<CurrentFile>,
}

struct Entry {
    name: String,
    method: u16,
    crc32: u32,
    compressed_size: u32,
    uncompressed_size: u32,
    lfh_offset: u32,
}

struct CurrentFile {
    name: String,
    method: u16,
    lfh_offset: u64,
    uncompressed_size: u64,
    compressed_size: u64,
    crc: Hasher,
    deflate: Option<Compress>,
}

impl<W: Write + Seek> ZipWriter<W> {
    pub fn new(inner: W) -> Self {
        Self {
            inner,
            entries: Vec::new(),
            cur: None,
        }
    }

    /// Begin a new entry. Returns the LFH size (bytes), needed by
    /// `AppxBlockMap.xml`'s `LfhSize` attribute.
    pub fn start_file(&mut self, name: &str, compress: bool) -> Result<u32> {
        if self.cur.is_some() {
            return Err(MsixError::InvalidState(
                "start_file called while a previous file is still open",
            ));
        }
        if name.len() > u16::MAX as usize {
            return Err(MsixError::Zip32Limit {
                what: "file name length (bytes)",
                limit: u16::MAX as u64,
            });
        }
        let lfh_offset = self.inner.stream_position()?;
        let method = if compress { METHOD_DEFLATE } else { METHOD_STORED };

        write_lfh(&mut self.inner, name, method, 0, 0, 0)?;
        // name.len() ≤ u16::MAX < u32::MAX, so 30 + len always fits in u32.
        let lfh_size = 30 + name.len() as u32;

        self.cur = Some(CurrentFile {
            name: name.to_string(),
            method,
            lfh_offset,
            uncompressed_size: 0,
            compressed_size: 0,
            crc: Hasher::new(),
            deflate: compress.then(|| Compress::new(Compression::best(), false)),
        });
        Ok(lfh_size)
    }

    /// Write one block of raw payload. Returns bytes appended to the archive
    /// for this block (after compression, if applicable).
    pub fn write_block(&mut self, raw: &[u8]) -> Result<u32> {
        let cur = self.cur.as_mut().ok_or(MsixError::InvalidState(
            "write_block called with no open file",
        ))?;
        cur.crc.update(raw);
        cur.uncompressed_size += raw.len() as u64;

        if let Some(c) = cur.deflate.as_mut() {
            let written = deflate_block(c, raw, &mut self.inner, FlushCompress::Full)?;
            cur.compressed_size += written as u64;
            Ok(written)
        } else {
            self.inner.write_all(raw)?;
            cur.compressed_size += raw.len() as u64;
            Ok(raw.len() as u32)
        }
    }

    /// Close the current entry: finish deflate, patch the LFH with real
    /// sizes/CRC, and record the entry for the central directory.
    pub fn end_file(&mut self) -> Result<()> {
        let mut cur = self
            .cur
            .take()
            .ok_or(MsixError::InvalidState("end_file called with no open file"))?;

        if let Some(c) = cur.deflate.as_mut() {
            let extra = deflate_block(c, &[], &mut self.inner, FlushCompress::Finish)?;
            cur.compressed_size += extra as u64;
        }

        let crc = cur.crc.clone().finalize();
        let comp = u32_zip_limit(cur.compressed_size, "compressed entry size")?;
        let uncomp = u32_zip_limit(cur.uncompressed_size, "uncompressed entry size")?;
        let lfh_off = u32_zip_limit(cur.lfh_offset, "archive offset")?;

        // Patch the LFH (preserving its size — only CRC / sizes change).
        let after = self.inner.stream_position()?;
        self.inner.seek(SeekFrom::Start(cur.lfh_offset))?;
        write_lfh(&mut self.inner, &cur.name, cur.method, crc, comp, uncomp)?;
        self.inner.seek(SeekFrom::Start(after))?;

        self.entries.push(Entry {
            name: cur.name,
            method: cur.method,
            crc32: crc,
            compressed_size: comp,
            uncompressed_size: uncomp,
            lfh_offset: lfh_off,
        });
        Ok(())
    }

    /// Current byte position in the underlying stream. Call immediately
    /// after `start_file()` to learn the offset where the entry's file
    /// data begins — needed for `AppxBundleManifest.xml`'s `Offset=` attr.
    pub fn position(&mut self) -> Result<u64> {
        Ok(self.inner.stream_position()?)
    }

    /// Write central directory + EOCD and return the wrapped writer.
    pub fn finish(mut self) -> Result<W> {
        if self.cur.is_some() {
            return Err(MsixError::InvalidState(
                "finish called with a file still open",
            ));
        }

        let cd_offset = self.inner.stream_position()?;
        for e in &self.entries {
            write_cdh(&mut self.inner, e)?;
        }
        let cd_end = self.inner.stream_position()?;
        let cd_size = u32_zip_limit(cd_end - cd_offset, "central directory size")?;
        let cd_offset_u32 = u32_zip_limit(cd_offset, "central directory offset")?;
        let entry_count = u16::try_from(self.entries.len()).map_err(|_| MsixError::Zip32Limit {
            what: "entry count",
            limit: u16::MAX as u64,
        })?;

        write_eocd(&mut self.inner, entry_count, cd_size, cd_offset_u32)?;
        Ok(self.inner)
    }
}

fn deflate_block<W: Write>(
    c: &mut Compress,
    input: &[u8],
    out: &mut W,
    flush: FlushCompress,
) -> Result<u32> {
    let mut buf = [0u8; 64 * 1024];
    let mut written = 0u32;
    let mut in_pos = 0usize;
    loop {
        let before_in = c.total_in();
        let before_out = c.total_out();
        let status = c
            .compress(&input[in_pos..], &mut buf, flush)
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        let consumed = (c.total_in() - before_in) as usize;
        let produced = (c.total_out() - before_out) as usize;

        if produced > 0 {
            out.write_all(&buf[..produced])?;
            written = written.checked_add(produced as u32).ok_or(MsixError::Zip32Limit {
                what: "compressed block size",
                limit: u32::MAX as u64,
            })?;
        }
        in_pos += consumed;

        // Termination:
        // - StreamEnd: Finish flush completed, deflate stream done.
        // - Output buffer NOT fully filled: the compressor had room left and
        //   chose to stop, so it has no more pending output for this flush op.
        //   (Z_FULL_FLUSH always emits a sync marker; the check must be
        //   "output had room left" rather than "produced == 0", otherwise the
        //   marker from each iteration tricks us into looping forever.)
        if matches!(status, Status::StreamEnd) {
            break;
        }
        if produced < buf.len() {
            break;
        }
        // Output buffer was filled to the brim; loop to drain remaining bytes.
    }
    Ok(written)
}

/// `name` length is pre-validated by `start_file` to fit in `u16`, and entries
/// in `Entry` came from `start_file` as well — so `name_len_u16` succeeds for
/// every internal caller. Returns an error rather than panicking on the
/// theoretical violation.
fn write_lfh<W: Write>(
    w: &mut W,
    name: &str,
    method: u16,
    crc32: u32,
    compressed_size: u32,
    uncompressed_size: u32,
) -> Result<()> {
    let name_len = name_len_u16(name)?;
    w.write_all(&LFH_SIG.to_le_bytes())?;
    w.write_all(&VERSION_NEEDED.to_le_bytes())?;
    w.write_all(&GP_FLAG_UTF8.to_le_bytes())?;
    w.write_all(&method.to_le_bytes())?;
    w.write_all(&dos_time().to_le_bytes())?;
    w.write_all(&dos_date().to_le_bytes())?;
    w.write_all(&crc32.to_le_bytes())?;
    w.write_all(&compressed_size.to_le_bytes())?;
    w.write_all(&uncompressed_size.to_le_bytes())?;
    w.write_all(&name_len.to_le_bytes())?;
    w.write_all(&0u16.to_le_bytes())?; // extra field length
    w.write_all(name.as_bytes())?;
    Ok(())
}

fn write_cdh<W: Write>(w: &mut W, e: &Entry) -> Result<()> {
    let name_len = name_len_u16(&e.name)?;
    w.write_all(&CDH_SIG.to_le_bytes())?;
    w.write_all(&VERSION_MADE_BY.to_le_bytes())?;
    w.write_all(&VERSION_NEEDED.to_le_bytes())?;
    w.write_all(&GP_FLAG_UTF8.to_le_bytes())?;
    w.write_all(&e.method.to_le_bytes())?;
    w.write_all(&dos_time().to_le_bytes())?;
    w.write_all(&dos_date().to_le_bytes())?;
    w.write_all(&e.crc32.to_le_bytes())?;
    w.write_all(&e.compressed_size.to_le_bytes())?;
    w.write_all(&e.uncompressed_size.to_le_bytes())?;
    w.write_all(&name_len.to_le_bytes())?;
    w.write_all(&0u16.to_le_bytes())?; // extra
    w.write_all(&0u16.to_le_bytes())?; // comment
    w.write_all(&0u16.to_le_bytes())?; // disk start
    w.write_all(&0u16.to_le_bytes())?; // internal attrs
    w.write_all(&0u32.to_le_bytes())?; // external attrs
    w.write_all(&e.lfh_offset.to_le_bytes())?;
    w.write_all(e.name.as_bytes())?;
    Ok(())
}

fn name_len_u16(name: &str) -> Result<u16> {
    u16::try_from(name.len()).map_err(|_| MsixError::Zip32Limit {
        what: "file name length (bytes)",
        limit: u16::MAX as u64,
    })
}

fn write_eocd<W: Write>(
    w: &mut W,
    entry_count: u16,
    cd_size: u32,
    cd_offset: u32,
) -> Result<()> {
    w.write_all(&EOCD_SIG.to_le_bytes())?;
    w.write_all(&0u16.to_le_bytes())?; // disk number
    w.write_all(&0u16.to_le_bytes())?; // disk with CD
    w.write_all(&entry_count.to_le_bytes())?; // entries on this disk
    w.write_all(&entry_count.to_le_bytes())?; // total entries
    w.write_all(&cd_size.to_le_bytes())?;
    w.write_all(&cd_offset.to_le_bytes())?;
    w.write_all(&0u16.to_le_bytes())?; // comment length
    Ok(())
}

/// Constant epoch (1980-01-01 00:00:00 — the earliest MS-DOS time) for
/// deterministic output. MSIX tooling doesn't care about timestamps.
fn dos_date() -> u16 {
    ((1 << 5) | 1) as u16
}
fn dos_time() -> u16 {
    0
}

fn u32_zip_limit(v: u64, what: &'static str) -> Result<u32> {
    u32::try_from(v).map_err(|_| MsixError::Zip32Limit {
        what,
        limit: u32::MAX as u64,
    })
}
