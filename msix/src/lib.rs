//! Pure-Rust MSIX package + `.msixbundle` creation.
//!
//! Pack mirrors the structure of Microsoft's MSIX SDK pack pipeline
//! (`src/msix/pack/` in microsoft/msix-packaging), reimplemented from scratch
//! against the documented MSIX/APPX format. Bundle has no MS open-source
//! reference (the SDK only unpacks bundles); layout is reverse-engineered
//! from a known-good `.msixbundle`. No FFI, no CMake, no Windows runtime.

mod block_map;
mod bundle;
mod content_types;
mod package_writer;
mod zip_writer;

pub use bundle::{bundle, Architecture, BundleIdentity, ContainedPackage};
pub use package_writer::{pack, PackOptions};

#[derive(thiserror::Error, Debug)]
pub enum MsixError {
    #[error("source directory missing AppxManifest.xml: {0}")]
    ManifestMissing(std::path::PathBuf),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("xml: {0}")]
    Xml(#[from] quick_xml::Error),
}

pub type Result<T> = std::result::Result<T, MsixError>;
