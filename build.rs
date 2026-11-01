fn main() {
    for dir in ["/opt/homebrew/lib", "/usr/local/lib"] {
        if std::path::Path::new(dir).exists() {
            println!("cargo:rustc-link-search=native={dir}");
            println!("cargo:rustc-link-arg=-Wl,-rpath,{dir}");
        }
    }
}
