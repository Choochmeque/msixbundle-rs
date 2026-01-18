use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const MSIX_SDK_COMMIT: &str = "efeb9da";
const MSIX_SDK_REPO: &str = "https://github.com/microsoft/msix-packaging";

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR not set"));
    let sdk_dir = out_dir.join("msix-packaging");

    // Clone or update the MSIX SDK repository
    if !sdk_dir.exists() {
        clone_sdk(&sdk_dir);
    }

    // Build the SDK using CMake
    let lib_dir = build_sdk(&sdk_dir, &out_dir);

    // Generate bindings with bindgen
    generate_bindings(&sdk_dir, &out_dir);

    // Output cargo directives
    println!("cargo:rustc-link-search=native={}", lib_dir.display());
    println!("cargo:rustc-link-lib=dylib=msix");

    // Link platform-specific dependencies
    link_platform_dependencies();

    println!("cargo:rerun-if-changed=build.rs");
}

fn clone_sdk(sdk_dir: &Path) {
    let status = Command::new("git")
        .args([
            "clone",
            MSIX_SDK_REPO,
            sdk_dir.to_str().expect("SDK path is not valid UTF-8"),
        ])
        .status()
        .expect("Failed to run git clone");

    if !status.success() {
        panic!("Failed to clone MSIX SDK repository");
    }

    // Checkout specific commit
    let status = Command::new("git")
        .args([
            "-C",
            sdk_dir.to_str().expect("SDK path is not valid UTF-8"),
            "checkout",
            MSIX_SDK_COMMIT,
        ])
        .status()
        .expect("Failed to run git checkout");

    if !status.success() {
        panic!("Failed to checkout commit {MSIX_SDK_COMMIT}");
    }
}

fn build_sdk(sdk_dir: &Path, out_dir: &Path) -> PathBuf {
    let build_dir = out_dir.join("build");
    fs::create_dir_all(&build_dir).expect("Failed to create build directory");

    let mut cmake_config = cmake::Config::new(sdk_dir);

    // Configure zlib from libz-sys
    let zlib_include = env::var("DEP_Z_INCLUDE").expect("DEP_Z_INCLUDE not set by libz-sys");
    let zlib_root = env::var("DEP_Z_ROOT").expect("DEP_Z_ROOT not set by libz-sys");
    cmake_config.define("ZLIB_INCLUDE_DIR", &zlib_include);
    cmake_config.define("ZLIB_ROOT", &zlib_root);
    let zlib_lib = PathBuf::from(&zlib_root).join("lib");
    cmake_config.define(
        "CMAKE_SHARED_LINKER_FLAGS",
        format!("-L{} -lz", zlib_lib.display()),
    );

    cmake_config
        .define("MSIX_PACK", "ON")
        .define("USE_VALIDATION_PARSER", "ON")
        .define("MSIX_TESTS", "OFF")
        .define("MSIX_SAMPLES", "OFF")
        .define("SKIP_BUNDLES", "OFF")
        .out_dir(&build_dir)
        .build_target("msix");

    // Platform-specific configuration
    let target = env::var("TARGET").expect("TARGET not set");

    if target.contains("windows") {
        cmake_config.define("WIN32", "ON");
        cmake_config.define("USE_STATIC_MSVC", "ON");
        cmake_config.define("XML_PARSER", "msxml6");
        cmake_config.define("CRYPTO_LIB", "crypt32");
    } else if target.contains("apple") {
        cmake_config.define("MACOS", "ON");
        cmake_config.define("XML_PARSER", "applexml");
        cmake_config.define("CRYPTO_LIB", "openssl");
    } else if target.contains("linux") {
        cmake_config.define("LINUX", "ON");
        cmake_config.define("XML_PARSER", "xerces");
        cmake_config.define("CRYPTO_LIB", "openssl");
    }

    let dst = cmake_config.build();

    dst.join("build").join("lib")
}

fn generate_bindings(sdk_dir: &Path, out_dir: &Path) {
    let header_dir = sdk_dir.join("src/inc/public");
    let header = header_dir.join("AppxPackaging.hpp");

    println!("cargo:rerun-if-changed={}", header.display());

    let bindings = bindgen::Builder::default()
        .header(header.to_str().expect("Header path is not valid UTF-8"))
        .clang_arg(format!("-I{}", header_dir.display()))
        // Only generate bindings for the functions we need
        .allowlist_function("PackPackage")
        .allowlist_function("UnpackPackage")
        .allowlist_function("UnpackBundle")
        .allowlist_function("PackBundle")
        .allowlist_function("CoCreateAppxFactory")
        .allowlist_function("CoCreateAppxBundleFactory")
        // Include necessary types
        .allowlist_type("MSIX_PACKUNPACK_OPTION")
        .allowlist_type("MSIX_VALIDATION_OPTION")
        .allowlist_type("MSIX_APPLICABILITY_OPTIONS")
        .allowlist_type("MSIX_BUNDLE_OPTIONS")
        .allowlist_type("HRESULT")
        // Generate constants
        .allowlist_var("S_OK")
        .allowlist_var("S_FALSE")
        .allowlist_var("E_.*")
        // Treat as opaque (we don't need the full COM interface definitions)
        .opaque_type("IAppx.*")
        // Layout tests can fail on cross-compilation
        .layout_tests(false)
        .generate()
        .expect("Failed to generate bindings");

    let bindings_path = out_dir.join("bindings.rs");
    bindings
        .write_to_file(&bindings_path)
        .expect("Failed to write bindings");
}

fn link_platform_dependencies() {
    let target = env::var("TARGET").expect("TARGET not set");

    if target.contains("windows") {
        println!("cargo:rustc-link-lib=oleaut32");
        println!("cargo:rustc-link-lib=ole32");
        println!("cargo:rustc-link-lib=bcrypt");
        println!("cargo:rustc-link-lib=crypt32");
        println!("cargo:rustc-link-lib=shlwapi");
        println!("cargo:rustc-link-lib=z");
    } else if target.contains("apple") {
        println!("cargo:rustc-link-lib=framework=CoreFoundation");
        println!("cargo:rustc-link-lib=framework=Security");
        println!("cargo:rustc-link-lib=c++");
        // zlib is required for compression
        println!("cargo:rustc-link-lib=z");
        // OpenSSL is required on macOS
        if let Ok(openssl_dir) = env::var("OPENSSL_DIR") {
            println!("cargo:rustc-link-search=native={}/lib", openssl_dir);
        }
        println!("cargo:rustc-link-lib=ssl");
        println!("cargo:rustc-link-lib=crypto");
    } else if target.contains("linux") {
        println!("cargo:rustc-link-lib=stdc++");
        // zlib is required for compression
        println!("cargo:rustc-link-lib=z");
        // Xerces-C is required on Linux
        println!("cargo:rustc-link-lib=xerces-c");
        // OpenSSL is required on Linux
        println!("cargo:rustc-link-lib=ssl");
        println!("cargo:rustc-link-lib=crypto");
    }
}
