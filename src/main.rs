fn main() {
    println!(
        "muobserve v{} initialized (hot retention window: {} days)",
        env!("CARGO_PKG_VERSION"),
        muobserve::DEFAULT_HOT_RETENTION_DAYS
    );
}
