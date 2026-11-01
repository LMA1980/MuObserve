use std::path::PathBuf;

use muobserve::{execute_cli_command, parse_cli_args, HotDuckDbStore, McpServer};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("mcp-stdio") {
        let store = HotDuckDbStore::open_in_memory().expect("failed to initialize HotDuckDbStore");
        let mcp = McpServer::new(store);
        let stdin = std::io::stdin();
        let stdout = std::io::stdout();
        if let Err(e) = mcp.serve_stdio(stdin.lock(), stdout.lock()) {
            eprintln!("muobserve mcp-stdio error: {e}");
            std::process::exit(1);
        }
        return;
    }

    if !args.is_empty() {
        match parse_cli_args(&args) {
            Ok((db_path, cmd)) => {
                let parquet_root = db_path
                    .as_ref()
                    .and_then(|p| p.parent().map(|dir| dir.join("parquet")));
                let store = HotDuckDbStore::open(db_path.as_deref(), parquet_root.as_deref())
                    .expect("failed to open HotDuckDbStore");
                match execute_cli_command(&store, &cmd) {
                    Ok(out) => {
                        println!("{}", serde_json::to_string_pretty(&out).unwrap_or_default());
                        return;
                    }
                    Err(e) => {
                        eprintln!("muobserve error: {e}");
                        std::process::exit(1);
                    }
                }
            }
            Err(_) => {
                let _ = PathBuf::new();
            }
        }
    }

    println!(
        "muobserve v{} initialized (hot retention window: {} days)",
        env!("CARGO_PKG_VERSION"),
        muobserve::DEFAULT_HOT_RETENTION_DAYS
    );
}
