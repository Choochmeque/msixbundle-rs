//! `AppxSignature.p7x` generation.
//!
//! Mirrors xbuild's `msix::p7x` (which itself matches MS SignTool output):
//! compute four SHA-256 digests over specific package regions, wrap them
//! in an `SpcIndirectDataContent` (with the MS `SpcSipInfo` blob), embed in
//! a CMS `SignedData`, prefix the DER bytes with the `PKCX` magic, and append
//! as `AppxSignature.p7x` to the package.
//!
//! The package must already declare `<Override PartName="/AppxSignature.p7x"
//! ContentType="application/vnd.ms-appx.signature"/>` in `[Content_Types].xml`
//! (our `pack`/`bundle` always emit this), so signing doesn't have to rewrite
//! content types — which would invalidate AXCT.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use rasn::prelude::*;
use rasn_cms::pkcs7_compat::{EncapsulatedContentInfo, SignedData};
use rasn_cms::{
    AlgorithmIdentifier, CONTENT_SIGNED_DATA, ContentInfo, IssuerAndSerialNumber, SignerIdentifier,
    SignerInfo,
};
use rasn_pkix::{Attribute, Certificate};
use rsa::RsaPrivateKey;
use rsa::pkcs1v15::SigningKey;
use rsa::pkcs8::DecodePrivateKey;
use sha2::{Digest, Sha256};
use signature::{SignatureEncoding, Signer as _};

use crate::{MsixError, Result};

const P7X_MAGIC: u32 = 0x504b_4358;

const SPC_INDIRECT_DATA_OBJID: &Oid = Oid::const_new(&[1, 3, 6, 1, 4, 1, 311, 2, 1, 4]);
const SPC_SP_OPUS_INFO_OBJID: &Oid = Oid::const_new(&[1, 3, 6, 1, 4, 1, 311, 2, 1, 12]);
const SPC_SIPINFO_OBJID: &Oid = Oid::const_new(&[1, 3, 6, 1, 4, 1, 311, 2, 1, 30]);

const APPX_SIGNATURE_NAME: &str = "AppxSignature.p7x";

// =============================================================================
// Public API: Signer trait + RSA/PEM impl + sign_package + Digests
// =============================================================================

/// Caller-provided signing identity. The MSIX p7x format needs both an X.509
/// certificate (for the SignerInfo's IssuerAndSerialNumber) and a private key
/// that can produce a SHA-256 + RSA-PKCS#1-v1.5 signature.
pub trait Signer {
    /// The signing certificate (leaf), parsed.
    fn certificate(&self) -> &Certificate;

    /// Sign `data` (raw bytes, not pre-hashed) with SHA-256 + RSA-PKCS#1-v1.5.
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>>;
}

/// RSA `Signer` — holds a private key plus an X.509 certificate (leaf).
/// Construct via [`RsaSigner::from_pem`] for a PEM bundle, or
/// [`RsaSigner::from_pfx`] for a PKCS#12 `.pfx` file.
pub struct RsaSigner {
    cert: Certificate,
    signing_key: SigningKey<Sha256>,
}

impl RsaSigner {
    /// Parse a PEM bundle containing both a PKCS#8 private key and an X.509
    /// certificate. Generated, for example, via:
    /// ```sh
    /// openssl req -newkey rsa:2048 -nodes -x509 -days 3650 \
    ///     -keyout key.pem -out cert.pem
    /// cat cert.pem key.pem > combined.pem
    /// ```
    pub fn from_pem(pem_bundle: &str) -> Result<Self> {
        let blocks = pem::parse_many(pem_bundle).map_err(|e| signing_err(&e.to_string()))?;
        let key_block = blocks
            .iter()
            .find(|b| b.tag() == "PRIVATE KEY")
            .ok_or_else(|| signing_err("no PRIVATE KEY block in PEM bundle"))?;
        let cert_block = blocks
            .iter()
            .find(|b| b.tag() == "CERTIFICATE")
            .ok_or_else(|| signing_err("no CERTIFICATE block in PEM bundle"))?;

        let key = RsaPrivateKey::from_pkcs8_der(key_block.contents())
            .map_err(|e| signing_err(&format!("decode PKCS#8 key: {e}")))?;
        let cert = rasn::der::decode::<Certificate>(cert_block.contents())
            .map_err(|e| signing_err(&format!("decode X.509 cert: {e}")))?;

        Ok(Self {
            cert,
            signing_key: SigningKey::<Sha256>::new(key),
        })
    }

    /// Parse a PKCS#12 (`.pfx`) blob. Uses the first entry that contains a
    /// private key + at least one certificate — matches the typical
    /// SignTool/MakeAppx PFX layout.
    pub fn from_pfx(pfx: &[u8], password: &str) -> Result<Self> {
        let store = p12_keystore::KeyStore::from_pkcs12(pfx, password)
            .map_err(|e| signing_err(&format!("parse PFX: {e}")))?;
        let (_, entry) = store
            .private_key_chain()
            .ok_or_else(|| signing_err("PFX has no private-key entry"))?;
        let key_der = entry.key();
        let leaf_der = entry
            .chain()
            .first()
            .ok_or_else(|| signing_err("PFX entry has no certificate"))?
            .as_der();

        let key = RsaPrivateKey::from_pkcs8_der(key_der)
            .map_err(|e| signing_err(&format!("decode PKCS#8 key from PFX: {e}")))?;
        let cert = rasn::der::decode::<Certificate>(leaf_der)
            .map_err(|e| signing_err(&format!("decode leaf cert from PFX: {e}")))?;

        Ok(Self {
            cert,
            signing_key: SigningKey::<Sha256>::new(key),
        })
    }
}

impl Signer for RsaSigner {
    fn certificate(&self) -> &Certificate {
        &self.cert
    }
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        let sig = self.signing_key.sign(data);
        Ok(sig.to_bytes().into())
    }
}

/// SHA-256 hashes of the four package regions that feed into
/// `AppxSignature.p7x`. (`AXCI` — content integrity — is intentionally
/// omitted; the MS catalog format is out of scope.)
#[derive(Clone, Debug)]
pub struct Digests {
    pub axpc: [u8; 32],
    pub axcd: [u8; 32],
    pub axct: [u8; 32],
    pub axbm: [u8; 32],
}

/// Compute the four digests for an existing (unsigned) MSIX package at `path`.
pub fn compute_digests(path: &Path) -> Result<Digests> {
    let bytes = std::fs::read(path)?;
    let (cd_offset, cd_end) = find_central_directory(&bytes)?;
    let axpc = sha256(&bytes[..cd_offset]);
    let axcd = sha256(&bytes[cd_offset..cd_end]);

    let f = File::open(path)?;
    let mut zip = zip::ZipArchive::new(f).map_err(zip_err)?;
    let axct = sha256_zip_entry(&mut zip, "[Content_Types].xml")?;
    let axbm = sha256_zip_entry(&mut zip, "AppxBlockMap.xml")?;

    Ok(Digests {
        axpc,
        axcd,
        axct,
        axbm,
    })
}

/// Sign an existing (unsigned) MSIX package in-place by appending an
/// `AppxSignature.p7x` zip entry and rewriting the central directory + EOCD.
/// The signature's `SpcSipInfo` GUID is picked from the file extension —
/// `.msixbundle` / `.appxbundle` get the APPXBUNDLE SIP, everything else
/// gets the APPX (single-package) SIP. SignTool rejects signatures whose
/// SIP GUID doesn't match the file type.
pub fn sign_package(path: &Path, signer: &dyn Signer) -> Result<()> {
    let digests = compute_digests(path)?;
    let kind = PackageKind::detect_from_path(path);
    let p7x_bytes = build_p7x(signer, &digests, kind)?;
    append_p7x_entry(path, &p7x_bytes)
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum PackageKind {
    /// `.msix` / `.appx`
    Package,
    /// `.msixbundle` / `.appxbundle`
    Bundle,
}

impl PackageKind {
    fn detect_from_path(p: &Path) -> Self {
        match p
            .extension()
            .and_then(|e| e.to_str())
            .map(|s| s.to_ascii_lowercase())
            .as_deref()
        {
            Some("msixbundle") | Some("appxbundle") => Self::Bundle,
            _ => Self::Package,
        }
    }

    /// SIP GUID embedded in `SpcSipInfoContent`. Values taken from
    /// osslsigncode's `appx.c` (matches what SignTool produces).
    fn sip_magic(self) -> [u8; 16] {
        match self {
            Self::Package => [
                0x4b, 0xdf, 0xc5, 0x0a, 0x07, 0xce, 0xe2, 0x4d, 0xb7, 0x6e, 0x23, 0xc8, 0x39, 0xa0,
                0x9f, 0xd1,
            ],
            Self::Bundle => [
                0xb3, 0x58, 0x5f, 0x0f, 0xde, 0xaa, 0x9a, 0x4b, 0xa4, 0x34, 0x95, 0x74, 0x2d, 0x92,
                0xec, 0xeb,
            ],
        }
    }
}

// =============================================================================
// Internal: P7X payload assembly (SPC_INDIRECT_DATA + CMS SignedData)
// =============================================================================

fn build_p7x(signer: &dyn Signer, digests: &Digests, kind: PackageKind) -> Result<Vec<u8>> {
    // 1) Build the inner payload. We wrap SpcIndirectData in `[0] EXPLICIT`
    //    via the `Payload` newtype, then put the resulting bytes into
    //    `EncapsulatedContentInfo.content` (which is itself `[explicit(0)]`).
    //    The double-wrap looks redundant per CMS but matches what
    //    SignTool-produced p7x files contain — verifiers expect it.
    let payload = Payload::encode(digests, kind)?;
    let encap_content_info = EncapsulatedContentInfo {
        content_type: SPC_INDIRECT_DATA_OBJID.into(),
        content: Some(Any::new(payload)),
    };

    // 2) Wrap in CMS SignedData (signed with the caller's RSA key).
    let signed_data = build_signed_data(signer, encap_content_info)?;

    // 3) Wrap that in CMS ContentInfo.
    let signed_der = rasn::der::encode(&signed_data).map_err(asn_err)?;
    let content_info = ContentInfo {
        content_type: CONTENT_SIGNED_DATA.into(),
        content: Any::new(signed_der),
    };

    // 4) DER-encode and prepend PKCX magic (big-endian).
    let info_der = rasn::der::encode(&content_info).map_err(asn_err)?;
    let mut out = Vec::with_capacity(4 + info_der.len());
    out.extend_from_slice(&P7X_MAGIC.to_be_bytes());
    out.extend_from_slice(&info_der);
    Ok(out)
}

#[allow(clippy::mutable_key_type)]
fn build_signed_data(
    signer: &dyn Signer,
    encap_content_info: EncapsulatedContentInfo,
) -> Result<SignedData> {
    // Per CMS spec: messageDigest signed attribute = SHA-256 of the eContent
    // *value* bytes (without the surrounding `[0] EXPLICIT` tag+length that
    // EncapsulatedContentInfo wraps it in). The *signature* is over the DER
    // encoding of the SignedAttributes SET (not over eContent).
    let inner_any = encap_content_info
        .content
        .as_ref()
        .ok_or_else(|| MsixError::Io(std::io::Error::other("missing eContent")))?;
    // Skip the outer EncapsulatedContentInfo `[0]` wrap AND the inner
    // `Payload` `[0]` wrap to reach the SpcIndirectData SEQUENCE bytes.
    let inner = strip_explicit_zero(strip_explicit_zero(inner_any.as_bytes()));
    let digest = Sha256::digest(inner);
    let cert = signer.certificate();

    let digest_algorithm = AlgorithmIdentifier {
        algorithm:
            Oid::JOINT_ISO_ITU_T_COUNTRY_US_ORGANIZATION_GOV_CSOR_NIST_ALGORITHMS_HASH_SHA256.into(),
        parameters: Some(Any::new(vec![5, 0])),
    };

    let mut signed_attrs = SetOf::default();
    signed_attrs.insert(Attribute {
        r#type: Oid::ISO_MEMBER_BODY_US_RSADSI_PKCS9_CONTENT_TYPE.into(),
        values: {
            let oid = ObjectIdentifier::from(SPC_INDIRECT_DATA_OBJID);
            let mut s = SetOf::default();
            s.insert(Any::new(rasn::der::encode(&oid).map_err(asn_err)?));
            s
        },
    });
    signed_attrs.insert(Attribute {
        r#type: Oid::ISO_MEMBER_BODY_US_RSADSI_PKCS9_MESSAGE_DIGEST.into(),
        values: {
            let d = OctetString::from(digest.to_vec());
            let mut s = SetOf::default();
            s.insert(Any::new(rasn::der::encode(&d).map_err(asn_err)?));
            s
        },
    });
    signed_attrs.insert(Attribute {
        r#type: SPC_SP_OPUS_INFO_OBJID.into(),
        values: SetOf::default(),
    });

    // Sign the DER encoding of the SignedAttributes SET. rasn encodes SetOf
    // standalone with the natural SET tag (0x31); inside SignerInfo this
    // same field gets re-tagged [0] IMPLICIT, but the signature is computed
    // over the SET-tagged encoding.
    let signed_attrs_der = rasn::der::encode(&signed_attrs).map_err(asn_err)?;
    let signature = signer.sign(&signed_attrs_der)?;

    let signer_info = SignerInfo {
        version: 1.into(),
        sid: SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
            issuer: cert.tbs_certificate.issuer.clone(),
            serial_number: cert.tbs_certificate.serial_number.clone(),
        }),
        digest_algorithm: digest_algorithm.clone(),
        signed_attrs: Some(signed_attrs),
        signature_algorithm: AlgorithmIdentifier {
            // rsaEncryption (1.2.840.113549.1.1.1). The bare `RSADSI_PKCS1`
            // constant is the prefix (1.2.840.113549.1.1) which is *not* a
            // valid algorithm OID — SignTool rejects p7x signed with it.
            algorithm: Oid::ISO_MEMBER_BODY_US_RSADSI_PKCS1_RSA.into(),
            parameters: Some(Any::new(vec![5, 0])),
        },
        signature: OctetString::from(signature),
        unsigned_attrs: Some(SetOf::default()),
    };

    let mut digest_algorithms = SetOf::default();
    digest_algorithms.insert(digest_algorithm);
    let mut signer_infos = SetOf::default();
    signer_infos.insert(signer_info);

    // Embed the leaf certificate in SignedData. Self-signed test certs aren't
    // in any system store; without embedding, SignTool can't locate the
    // public key for the signature it's trying to verify.
    let mut certs = SetOf::default();
    certs.insert(rasn_cms::CertificateChoices::Certificate(Box::new(
        cert.clone(),
    )));

    // SignedData.version per CMS RFC 5652 §5.1: MUST be 3 when eContentType
    // is anything other than id-data. Ours is SPC_INDIRECT_DATA, so v3.
    Ok(SignedData {
        version: 3.into(),
        digest_algorithms,
        encap_content_info,
        certificates: Some(certs),
        crls: None,
        signer_infos,
    })
}

/// Strip the leading `[0] EXPLICIT` tag + DER length octets, ONCE per call,
/// returning the inner value bytes. The eContent in our p7x is double-wrapped
/// (outer `[0]` from EncapsulatedContentInfo, inner `[0]` from `Payload`);
/// we call this twice to reach the SpcIndirectData SEQUENCE that gets hashed.
fn strip_explicit_zero(bytes: &[u8]) -> &[u8] {
    if bytes.len() < 2 || bytes[0] != 0xA0 {
        return bytes;
    }
    let len_byte = bytes[1];
    let header_len = if len_byte < 0x80 {
        2 // tag (1) + short-form length (1)
    } else {
        2 + (len_byte & 0x7F) as usize // tag + (0x80|n) + n length octets
    };
    if header_len > bytes.len() {
        return bytes;
    }
    &bytes[header_len..]
}

// --- ASN.1 wire types (mirrors xbuild's p7x.rs) ----------------------------

#[derive(AsnType, Clone, Debug, Eq, Encode, PartialEq)]
#[rasn(tag(context, 0))]
struct Payload {
    indirect_data: SpcIndirectData,
}

impl Payload {
    fn encode(digests: &Digests, kind: PackageKind) -> Result<Vec<u8>> {
        rasn::der::encode(&Self {
            indirect_data: SpcIndirectData::new(digests, kind),
        })
        .map_err(asn_err)
    }
}

#[derive(AsnType, Clone, Debug, Eq, Encode, PartialEq)]
struct SpcIndirectData {
    sip_info: SpcSipInfo,
    content: SpcIndirectDataContent,
}

impl SpcIndirectData {
    fn new(digests: &Digests, kind: PackageKind) -> Self {
        // 4-byte tag + 32-byte hash per region.
        let mut payload = Vec::with_capacity(4 + (4 + 32) * 4);
        payload.extend_from_slice(b"APPX");
        payload.extend_from_slice(b"AXPC");
        payload.extend_from_slice(&digests.axpc);
        payload.extend_from_slice(b"AXCD");
        payload.extend_from_slice(&digests.axcd);
        payload.extend_from_slice(b"AXCT");
        payload.extend_from_slice(&digests.axct);
        payload.extend_from_slice(b"AXBM");
        payload.extend_from_slice(&digests.axbm);
        Self {
            sip_info: SpcSipInfo::for_kind(kind),
            content: SpcIndirectDataContent::new(payload),
        }
    }
}

#[derive(AsnType, Clone, Debug, Eq, Encode, PartialEq)]
struct SpcIndirectDataContent {
    oid: [Open; 2],
    payload: OctetString,
}

impl SpcIndirectDataContent {
    fn new(payload: Vec<u8>) -> Self {
        Self {
            oid: [
                Open::ObjectIdentifier(
                    Oid::JOINT_ISO_ITU_T_COUNTRY_US_ORGANIZATION_GOV_CSOR_NIST_ALGORITHMS_HASH_SHA256
                        .into(),
                ),
                Open::Null,
            ],
            payload: OctetString::from(payload),
        }
    }
}

#[derive(AsnType, Clone, Debug, Eq, Encode, PartialEq)]
struct SpcSipInfo {
    oid: ObjectIdentifier,
    data: SpcSipInfoContent,
}

impl SpcSipInfo {
    fn for_kind(kind: PackageKind) -> Self {
        Self {
            oid: SPC_SIPINFO_OBJID.into(),
            data: SpcSipInfoContent::for_kind(kind),
        }
    }
}

#[derive(AsnType, Clone, Debug, Eq, Encode, PartialEq)]
struct SpcSipInfoContent {
    i1: u32,
    s1: OctetString,
    i2: u32,
    i3: u32,
    i4: u32,
    i5: u32,
    i6: u32,
}

impl SpcSipInfoContent {
    fn for_kind(kind: PackageKind) -> Self {
        // Version magic is the same for both kinds; only the embedded SIP
        // GUID differs (per osslsigncode's appx.c).
        const SPC_SIPINFO_MAGIC_INT: u32 = 0x0101_0000;
        Self {
            i1: SPC_SIPINFO_MAGIC_INT,
            s1: OctetString::from(kind.sip_magic().to_vec()),
            i2: 0,
            i3: 0,
            i4: 0,
            i5: 0,
            i6: 0,
        }
    }
}

// =============================================================================
// Internal: zip file mutation — append p7x entry and rewrite CD + EOCD
// =============================================================================

/// Append a single STORED entry named `AppxSignature.p7x` containing
/// `payload`, then rewrite the central directory + EOCD in place. The
/// original CD is preserved verbatim; we just append one new CDH for p7x and
/// emit a new EOCD with `count + 1` and the updated CD size.
fn append_p7x_entry(path: &Path, payload: &[u8]) -> Result<()> {
    let original = std::fs::read(path)?;
    let (cd_offset, cd_end) = find_central_directory(&original)?;
    // EOCD sits immediately after the CD (assuming no zip comment, which
    // we don't emit). `total_entries` is at EOCD + 10.
    let entry_count_in_eocd = read_u16_le(&original, cd_end + 10)?;

    let mut f = OpenOptions::new().read(true).write(true).open(path)?;
    f.set_len(cd_offset as u64)?;
    f.seek(SeekFrom::Start(cd_offset as u64))?;

    // 1) Write LFH + data for the new entry.
    let lfh_offset = cd_offset as u32;
    write_lfh(&mut f, APPX_SIGNATURE_NAME, payload)?;
    f.write_all(payload)?;

    // 2) Re-emit the original CD verbatim, then append the new CDH for p7x.
    let cd_start_new = f.stream_position()?;
    f.write_all(&original[cd_offset..cd_end])?;
    let new_cdh_size = write_cdh(&mut f, APPX_SIGNATURE_NAME, payload, lfh_offset)?;

    // 3) New EOCD.
    let cd_size_new = (cd_end - cd_offset) as u32 + new_cdh_size;
    let count_new = entry_count_in_eocd + 1;
    write_eocd(&mut f, count_new, cd_size_new, cd_start_new as u32)?;

    f.flush()?;
    Ok(())
}

// --- Local ZIP writers (no_compression, UTF-8 filename) --------------------

const LFH_SIG: u32 = 0x0403_4b50;
const CDH_SIG: u32 = 0x0201_4b50;
const EOCD_SIG: u32 = 0x0605_4b50;
const VERSION_NEEDED: u16 = 20;
const VERSION_MADE_BY: u16 = (3 << 8) | 63;
const GP_FLAG_UTF8: u16 = 1 << 11;
const METHOD_STORED: u16 = 0;

fn write_lfh<W: Write>(w: &mut W, name: &str, payload: &[u8]) -> Result<()> {
    let crc = crc32fast::hash(payload);
    let size = u32::try_from(payload.len()).map_err(|_| MsixError::Zip32Limit {
        what: "signature entry size",
        limit: u32::MAX as u64,
    })?;
    let name_len = u16::try_from(name.len()).map_err(|_| MsixError::Zip32Limit {
        what: "file name length",
        limit: u16::MAX as u64,
    })?;
    w.write_all(&LFH_SIG.to_le_bytes())?;
    w.write_all(&VERSION_NEEDED.to_le_bytes())?;
    w.write_all(&GP_FLAG_UTF8.to_le_bytes())?;
    w.write_all(&METHOD_STORED.to_le_bytes())?;
    w.write_all(&0u16.to_le_bytes())?; // dos time (epoch)
    w.write_all(&0x0021u16.to_le_bytes())?; // dos date (1980-01-01)
    w.write_all(&crc.to_le_bytes())?;
    w.write_all(&size.to_le_bytes())?; // compressed
    w.write_all(&size.to_le_bytes())?; // uncompressed
    w.write_all(&name_len.to_le_bytes())?;
    w.write_all(&0u16.to_le_bytes())?; // extra
    w.write_all(name.as_bytes())?;
    Ok(())
}

fn write_cdh<W: Write>(w: &mut W, name: &str, payload: &[u8], lfh_offset: u32) -> Result<u32> {
    let crc = crc32fast::hash(payload);
    let size = u32::try_from(payload.len()).map_err(|_| MsixError::Zip32Limit {
        what: "signature entry size",
        limit: u32::MAX as u64,
    })?;
    let name_len = u16::try_from(name.len()).map_err(|_| MsixError::Zip32Limit {
        what: "file name length",
        limit: u16::MAX as u64,
    })?;
    w.write_all(&CDH_SIG.to_le_bytes())?;
    w.write_all(&VERSION_MADE_BY.to_le_bytes())?;
    w.write_all(&VERSION_NEEDED.to_le_bytes())?;
    w.write_all(&GP_FLAG_UTF8.to_le_bytes())?;
    w.write_all(&METHOD_STORED.to_le_bytes())?;
    w.write_all(&0u16.to_le_bytes())?;
    w.write_all(&0x0021u16.to_le_bytes())?;
    w.write_all(&crc.to_le_bytes())?;
    w.write_all(&size.to_le_bytes())?;
    w.write_all(&size.to_le_bytes())?;
    w.write_all(&name_len.to_le_bytes())?;
    w.write_all(&0u16.to_le_bytes())?; // extra
    w.write_all(&0u16.to_le_bytes())?; // comment
    w.write_all(&0u16.to_le_bytes())?; // disk
    w.write_all(&0u16.to_le_bytes())?; // internal attrs
    w.write_all(&0u32.to_le_bytes())?; // external attrs
    w.write_all(&lfh_offset.to_le_bytes())?;
    w.write_all(name.as_bytes())?;
    Ok(46 + u32::from(name_len))
}

fn write_eocd<W: Write>(w: &mut W, entry_count: u16, cd_size: u32, cd_offset: u32) -> Result<()> {
    w.write_all(&EOCD_SIG.to_le_bytes())?;
    w.write_all(&0u16.to_le_bytes())?;
    w.write_all(&0u16.to_le_bytes())?;
    w.write_all(&entry_count.to_le_bytes())?;
    w.write_all(&entry_count.to_le_bytes())?;
    w.write_all(&cd_size.to_le_bytes())?;
    w.write_all(&cd_offset.to_le_bytes())?;
    w.write_all(&0u16.to_le_bytes())?;
    Ok(())
}

// =============================================================================
// Internal: helpers
// =============================================================================

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

fn sha256_zip_entry(zip: &mut zip::ZipArchive<File>, name: &str) -> Result<[u8; 32]> {
    let mut entry = zip.by_name(name).map_err(|_| {
        MsixError::Io(std::io::Error::other(format!(
            "zip entry not found: {name}"
        )))
    })?;
    let mut buf = Vec::with_capacity(entry.size() as usize);
    entry.read_to_end(&mut buf)?;
    Ok(sha256(&buf))
}

fn find_central_directory(bytes: &[u8]) -> Result<(usize, usize)> {
    const EOCD_MIN: usize = 22;
    const MAX_COMMENT: usize = 65535;
    if bytes.len() < EOCD_MIN {
        return Err(MsixError::Io(std::io::Error::other(
            "file smaller than EOCD record",
        )));
    }
    let last = bytes.len() - EOCD_MIN;
    let first = last.saturating_sub(MAX_COMMENT);
    for pos in (first..=last).rev() {
        let sig = read_u32_le(bytes, pos)?;
        if sig == EOCD_SIG {
            let cd_size = read_u32_le(bytes, pos + 12)? as usize;
            let cd_offset = read_u32_le(bytes, pos + 16)? as usize;
            if cd_offset.saturating_add(cd_size) > bytes.len() {
                return Err(MsixError::Io(std::io::Error::other(
                    "EOCD points past end of file",
                )));
            }
            return Ok((cd_offset, cd_offset + cd_size));
        }
    }
    Err(MsixError::Io(std::io::Error::other("EOCD not found")))
}

fn read_u32_le(bytes: &[u8], pos: usize) -> Result<u32> {
    let slice = bytes
        .get(pos..pos + 4)
        .ok_or_else(|| MsixError::Io(std::io::Error::other("u32 read out of bounds")))?;
    let arr: [u8; 4] = slice
        .try_into()
        .map_err(|_| MsixError::Io(std::io::Error::other("bad u32 slice")))?;
    Ok(u32::from_le_bytes(arr))
}

fn read_u16_le(bytes: &[u8], pos: usize) -> Result<u16> {
    let slice = bytes
        .get(pos..pos + 2)
        .ok_or_else(|| MsixError::Io(std::io::Error::other("u16 read out of bounds")))?;
    let arr: [u8; 2] = slice
        .try_into()
        .map_err(|_| MsixError::Io(std::io::Error::other("bad u16 slice")))?;
    Ok(u16::from_le_bytes(arr))
}

fn signing_err(s: &str) -> MsixError {
    MsixError::Io(std::io::Error::other(format!("signing: {s}")))
}
fn asn_err(e: rasn::error::EncodeError) -> MsixError {
    MsixError::Io(std::io::Error::other(format!("asn.1: {e}")))
}
fn zip_err(e: zip::result::ZipError) -> MsixError {
    MsixError::Io(std::io::Error::other(format!("zip: {e}")))
}
