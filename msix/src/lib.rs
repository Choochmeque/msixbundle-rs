//! Safe Rust wrapper for the Microsoft MSIX SDK.
//!
//! This crate provides a safe, ergonomic API for working with MSIX packages and bundles.

use std::ffi::CString;
use std::path::Path;

use msix_sys::{
    CoCreateAppxBundleFactory, CoCreateAppxFactory, IAppxBundleFactory, IAppxFactory,
    MSIX_APPLICABILITY_OPTIONS, MSIX_BUNDLE_OPTIONS, MSIX_PACKUNPACK_OPTION,
    MSIX_VALIDATION_OPTION,
};

/// Error type for MSIX operations.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("MSIX SDK error: HRESULT 0x{0:08X}")]
    Hresult(i32),

    #[error("Path contains invalid UTF-8: {0}")]
    InvalidPath(String),

    #[error("Path contains null byte: {0}")]
    NullByte(#[from] std::ffi::NulError),
}

pub type Result<T> = std::result::Result<T, Error>;

/// Validation options for MSIX operations.
#[derive(Debug, Clone, Copy, Default)]
pub struct ValidationOptions {
    pub skip_signature: bool,
    pub allow_signature_origin_unknown: bool,
    pub skip_package_validation: bool,
}

impl ValidationOptions {
    fn to_raw(self) -> MSIX_VALIDATION_OPTION {
        let mut flags = 0;
        if self.skip_signature {
            flags |= msix_sys::MSIX_VALIDATION_OPTION_MSIX_VALIDATION_OPTION_SKIPSIGNATURE;
        }
        if self.allow_signature_origin_unknown {
            flags |=
                msix_sys::MSIX_VALIDATION_OPTION_MSIX_VALIDATION_OPTION_ALLOWSIGNATUREORIGINUNKNOWN;
        }
        if self.skip_package_validation {
            flags |= msix_sys::MSIX_VALIDATION_OPTION_MSIX_VALIDATION_OPTION_SKIPPACKAGEVALIDATION;
        }
        flags
    }
}

/// Options for packing/unpacking MSIX packages.
#[derive(Debug, Clone, Copy, Default)]
pub struct PackageOptions {
    pub create_package_subfolder: bool,
    pub flat_structure: bool,
}

impl PackageOptions {
    fn to_raw(self) -> MSIX_PACKUNPACK_OPTION {
        let mut flags = 0;
        if self.create_package_subfolder {
            flags |= msix_sys::MSIX_PACKUNPACK_OPTION_MSIX_PACKUNPACK_OPTION_CREATEPACKAGESUBFOLDER;
        }
        if self.flat_structure {
            flags |=
                msix_sys::MSIX_PACKUNPACK_OPTION_MSIX_PACKUNPACK_OPTION_UNPACKWITHFLATSTRUCTURE;
        }
        flags
    }
}

/// Applicability options for bundle operations.
#[derive(Debug, Clone, Copy, Default)]
pub struct ApplicabilityOptions {
    pub skip_platform: bool,
    pub skip_language: bool,
}

impl ApplicabilityOptions {
    fn to_raw(self) -> MSIX_APPLICABILITY_OPTIONS {
        let mut flags = 0;
        if self.skip_platform {
            flags |= msix_sys::MSIX_APPLICABILITY_OPTIONS_MSIX_APPLICABILITY_OPTION_SKIPPLATFORM;
        }
        if self.skip_language {
            flags |= msix_sys::MSIX_APPLICABILITY_OPTIONS_MSIX_APPLICABILITY_OPTION_SKIPLANGUAGE;
        }
        flags
    }
}

/// Options for creating MSIX bundles.
#[derive(Debug, Clone, Copy, Default)]
pub struct BundleOptions {
    pub verbose: bool,
    pub overwrite: bool,
    pub flat_bundle: bool,
    pub bundle_manifest_only: bool,
}

impl BundleOptions {
    fn to_raw(self) -> MSIX_BUNDLE_OPTIONS {
        let mut flags = 0;
        if self.verbose {
            flags |= msix_sys::MSIX_BUNDLE_OPTIONS_MSIX_OPTION_VERBOSE;
        }
        if self.overwrite {
            flags |= msix_sys::MSIX_BUNDLE_OPTIONS_MSIX_OPTION_OVERWRITE;
        }
        if self.flat_bundle {
            flags |= msix_sys::MSIX_BUNDLE_OPTIONS_MSIX_BUNDLE_OPTION_FLATBUNDLE;
        }
        if self.bundle_manifest_only {
            flags |= msix_sys::MSIX_BUNDLE_OPTIONS_MSIX_BUNDLE_OPTION_BUNDLEMANIFESTONLY;
        }
        flags
    }
}

fn path_to_cstring(path: &Path) -> Result<CString> {
    let s = path
        .to_str()
        .ok_or_else(|| Error::InvalidPath(path.display().to_string()))?;
    Ok(CString::new(s)?)
}

fn check_hresult(hr: msix_sys::HRESULT) -> Result<()> {
    if msix_sys::succeeded(hr) {
        Ok(())
    } else {
        Err(Error::Hresult(hr as i32))
    }
}

/// Pack a directory into an MSIX package.
pub fn pack_package(
    source_dir: &Path,
    output: &Path,
    options: PackageOptions,
    validation_options: ValidationOptions,
) -> Result<()> {
    let source_dir = path_to_cstring(source_dir)?;
    let output = path_to_cstring(output)?;

    let hr = unsafe {
        msix_sys::PackPackage(
            options.to_raw(),
            validation_options.to_raw(),
            source_dir.as_ptr() as *mut _,
            output.as_ptr() as *mut _,
        )
    };

    check_hresult(hr)
}

/// Source for bundle creation.
pub enum BundleSource<'a> {
    /// Directory containing .msix files.
    Directory(&'a Path),
    /// Mapping file with [Files] section.
    MappingFile(&'a Path),
}

/// Pack multiple MSIX packages into a bundle.
pub fn pack_bundle(
    source: BundleSource<'_>,
    output: &Path,
    version: Option<&str>,
    options: BundleOptions,
) -> Result<()> {
    let output = path_to_cstring(output)?;
    let version = match version {
        Some(v) => Some(CString::new(v)?),
        None => None,
    };

    let (dir_cstr, map_cstr): (Option<CString>, Option<CString>) = match source {
        BundleSource::Directory(p) => (Some(path_to_cstring(p)?), None),
        BundleSource::MappingFile(p) => (None, Some(path_to_cstring(p)?)),
    };

    let hr = unsafe {
        msix_sys::PackBundle(
            options.to_raw(),
            dir_cstr
                .as_ref()
                .map(|c| c.as_ptr())
                .unwrap_or(std::ptr::null()) as *mut _,
            output.as_ptr() as *mut _,
            map_cstr
                .as_ref()
                .map(|c| c.as_ptr())
                .unwrap_or(std::ptr::null()) as *mut _,
            version
                .as_ref()
                .map(|c| c.as_ptr())
                .unwrap_or(std::ptr::null()) as *mut _,
        )
    };

    check_hresult(hr)
}

/// Unpack an MSIX package to a directory.
pub fn unpack_package(
    source: &Path,
    destination: &Path,
    options: PackageOptions,
    validation_options: ValidationOptions,
) -> Result<()> {
    let source = path_to_cstring(source)?;
    let destination = path_to_cstring(destination)?;

    let hr = unsafe {
        msix_sys::UnpackPackage(
            options.to_raw(),
            validation_options.to_raw(),
            source.as_ptr() as *mut _,
            destination.as_ptr() as *mut _,
        )
    };

    check_hresult(hr)
}

/// Unpack an MSIX bundle to a directory.
pub fn unpack_bundle(
    source: &Path,
    destination: &Path,
    options: PackageOptions,
    validation_options: ValidationOptions,
    applicability_options: ApplicabilityOptions,
) -> Result<()> {
    let source = path_to_cstring(source)?;
    let destination = path_to_cstring(destination)?;

    let hr = unsafe {
        msix_sys::UnpackBundle(
            options.to_raw(),
            validation_options.to_raw(),
            applicability_options.to_raw(),
            source.as_ptr() as *mut _,
            destination.as_ptr() as *mut _,
        )
    };

    check_hresult(hr)
}

/// RAII wrapper for IAppxFactory.
pub struct AppxFactory {
    ptr: *mut IAppxFactory,
}

impl AppxFactory {
    /// Create a new APPX factory.
    pub fn new(validation_options: ValidationOptions) -> Result<Self> {
        let mut ptr: *mut IAppxFactory = std::ptr::null_mut();
        let hr =
            unsafe { CoCreateAppxFactory(validation_options.to_raw(), &mut ptr as *mut *mut _) };
        check_hresult(hr)?;
        Ok(Self { ptr })
    }

    /// Get the raw pointer (for advanced usage).
    pub fn as_ptr(&self) -> *mut IAppxFactory {
        self.ptr
    }
}

/// RAII wrapper for IAppxBundleFactory.
pub struct AppxBundleFactory {
    ptr: *mut IAppxBundleFactory,
}

impl AppxBundleFactory {
    /// Create a new APPX bundle factory.
    pub fn new(
        validation_options: ValidationOptions,
        applicability_options: ApplicabilityOptions,
    ) -> Result<Self> {
        let mut ptr: *mut IAppxBundleFactory = std::ptr::null_mut();
        let hr = unsafe {
            CoCreateAppxBundleFactory(
                validation_options.to_raw(),
                applicability_options.to_raw(),
                &mut ptr as *mut *mut _,
            )
        };
        check_hresult(hr)?;
        Ok(Self { ptr })
    }

    /// Get the raw pointer (for advanced usage).
    pub fn as_ptr(&self) -> *mut IAppxBundleFactory {
        self.ptr
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validation_options_default() {
        let opts = ValidationOptions::default();
        assert_eq!(opts.to_raw(), 0);
    }

    #[test]
    fn test_package_options_default() {
        let opts = PackageOptions::default();
        assert_eq!(opts.to_raw(), 0);
    }
}
