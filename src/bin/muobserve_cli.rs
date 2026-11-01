use muobserve::{execute_cli_command, parse_cli_args, HotDuckDbStore};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (db_path, cmd) = match parse_cli_args(&args) {
        Ok(parsed) => parsed,
        Err(e) => {
            eprintln!("muobserve-cli error: {e}");
            std::process::exit(2);
        }
    };

    let parquet_root = db_path
        .as_ref()
        .and_then(|p| p.parent().map(|dir| dir.join("parquet")));
    let store = match HotDuckDbStore::open(db_path.as_deref(), parquet_root.as_deref()) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("muobserve-cli failed to open HotDuckDbStore: {e}");
            std::process::exit(1);
        }
    };

    match execute_cli_command(&store, &cmd) {
        Ok(val) => {
            println!("{}", serde_json::to_string_pretty(&val).unwrap_or_default());
        }
        Err(e) => {
            eprintln!("muobserve-cli execution error: {e}");
            std::process::exit(1);
        }
    }
}
