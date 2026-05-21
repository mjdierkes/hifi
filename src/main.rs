fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Some(result) = hifi::app::run_completion(args.as_slice()) {
        match result {
            Ok(code) => std::process::exit(code),
            Err(e) => {
                eprintln!("hifi: {e}");
                std::process::exit(2);
            }
        }
    }

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    match rt.block_on(hifi::app::run(args)) {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("hifi: {e}");
            std::process::exit(2);
        }
    }
}
