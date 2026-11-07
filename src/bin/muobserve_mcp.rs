use std::path::PathBuf;

use mu_observable_hub::{HotDuckDbStore, McpServer};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut db_path: Option<PathBuf> = std::env::var("MU_OBSERVABLE_DB_PATH")
        .or_else(|_| std::env::var("MUOBSERVE_DB_PATH"))
        .ok()
        .map(PathBuf::from);
    let mut parquet_root: Option<PathBuf> = std::env::var("MU_OBSERVABLE_PARQUET_ROOT")
        .or_else(|_| std::env::var("MUOBSERVE_PARQUET_ROOT"))
        .ok()
        .map(PathBuf::from);
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--db" => {
                if let Some(p) = args.get(i + 1) {
                    db_path = Some(PathBuf::from(p));
                }
                i += 2;
            }
            "--parquet-root" => {
                if let Some(p) = args.get(i + 1) {
                    parquet_root = Some(PathBuf::from(p));
                }
                i += 2;
            }
            _ => {
                i += 1;
            }
        }
    }

    let store = match HotDuckDbStore::open(db_path.as_deref(), parquet_root.as_deref()) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("mu-observable-mcp failed to open store: {e}");
            std::process::exit(1);
        }
    };

    let mcp = McpServer::new(store);
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    if let Err(e) = mcp.serve_stdio(stdin.lock(), stdout.lock()) {
        eprintln!("mu-observable-mcp stdio error: {e}");
        std::process::exit(1);
    }
}
