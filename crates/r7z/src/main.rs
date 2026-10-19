mod cli;

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let code = match cli::run(argv) {
        Ok(code) => code,
        Err(e) => {
            cli::ui::error(&e.to_string());
            if matches!(e, r7z::Error::Usage(_)) {
                eprintln!("Run 'r7z help' for usage.");
            }
            cli::exit_code_for(&e)
        }
    };
    std::process::exit(code);
}
