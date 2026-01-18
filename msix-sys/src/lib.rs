//! FFI bindings to the Microsoft MSIX SDK.
//!
//! This crate provides low-level bindings to the MSIX SDK for packing and unpacking
//! MSIX packages and bundles on any platform.
//!
//! For a safe, ergonomic API, use the `msix` crate instead.

#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(dead_code)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

/// Check if HRESULT indicates success
#[inline]
pub fn succeeded(hr: HRESULT) -> bool {
    hr >= 0
}

/// Check if HRESULT indicates failure
#[inline]
pub fn failed(hr: HRESULT) -> bool {
    hr < 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hresult_helpers() {
        assert!(succeeded(0));
        assert!(succeeded(1));
        assert!(failed(-1));
    }
}
