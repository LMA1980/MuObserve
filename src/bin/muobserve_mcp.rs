use std::path::PathBuf;

use muobserve::{HotDuckDbStore, McpServer};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut db_path: Option<PathBuf> = std::env::var("MUOBSERVE_DB_PATH").ok().map(PathBuf::from);
    let mut parquet_root: Option<PathBuf> = std::env::var("MUOBSERVE_PARQUET_ROOT")
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
            eprintln!("muobserve-mcp failed to open store: {e}");
            std::process::exit(1);
        }
    };

    let mcp = McpServer::new(store);
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    if let Err(e) = mcp.serve_stdio(stdin.lock(), stdout.lock()) {
        eprintln!("muobserve-mcp stdio error: {e}");
        std::process::exit(1);
    }
}
