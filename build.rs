fn main() {
    #[cfg(target_os = "macos")]
    {
        if std::path::Path::new("/opt/homebrew/lib/libduckdb.dylib").exists() {
            println!("cargo:rustc-link-search=native=/opt/homebrew/lib");
            println!("cargo:rustc-link-arg=-Wl,-rpath,/opt/homebrew/lib");
        }
        if std::path::Path::new("/usr/local/lib/libduckdb.dylib").exists() {
            println!("cargo:rustc-link-search=native=/usr/local/lib");
            println!("cargo:rustc-link-arg=-Wl,-rpath,/usr/local/lib");
        }
    }
}
