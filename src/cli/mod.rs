pub mod args;
pub mod commands;
pub mod ui;

use args::Command;
use r7z::error::{Error, Result};

pub const EXIT_OK: i32 = 0;
pub const EXIT_WARNING: i32 = 1;
pub const EXIT_FATAL: i32 = 2;
pub const EXIT_USAGE: i32 = 7;

pub fn run(argv: Vec<String>) -> Result<i32> {
    let a = args::parse(argv)?;
    match a.command {
        Command::Add => commands::add(&a),
        Command::Extract { full_paths } => commands::extract(&a, full_paths, false),
        Command::Test => commands::extract(&a, true, true),
        Command::List => commands::list(&a),
        Command::Hash => commands::hash(&a),
        Command::Bench => commands::bench(&a),
        Command::Info => commands::info(),
        Command::Version => {
            println!("r7z {}", env!("CARGO_PKG_VERSION"));
            Ok(EXIT_OK)
        }
        Command::Help => {
            commands::help();
            Ok(EXIT_OK)
        }
    }
}

pub fn exit_code_for(e: &Error) -> i32 {
    match e {
        Error::Usage(_) => EXIT_USAGE,
        _ => EXIT_FATAL,
    }
}
