//! Build-time glue for the lsposed native cdylib (`libvpnhide_checks.so`).
//!
//! Only purpose right now: align ELF LOAD segments on 16 KiB so the
//! library loads cleanly on 16 KiB-page Android devices (Pixel 8 Pro on
//! Android 16, and any future hardware that ships with 16 KiB pages by
//! default). NDK r28+ already does this by default, but passing the flag
//! explicitly keeps r27 builds compatible too — defence in depth.
//!
//! See: <https://developer.android.com/guide/practices/page-sizes>

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    // Align ELF LOAD segments on 16 KiB for 16 KiB-page devices
    println!("cargo:rustc-link-arg=-Wl,-z,max-page-size=16384");

    // Explicitly link libc (getifaddrs, freeifaddrs)
    // This must come before -nodefaultlibs in the final linker command
    println!("cargo:rustc-link-lib=c");
}
