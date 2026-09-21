//! Command-line entry point for the frame parsing laboratory.
//!
//! Demo:
//!   cargo run --locked -- --addr 127.0.0.1:5211

use frame_lab::server::Server;
use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    let mut addr = "127.0.0.1:5211".to_string();
    let mut data_dir = PathBuf::from("frame-lab-data");

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--addr" => {
                if let Some(value) = args.next() {
                    addr = value;
                }
            }
            "--data-dir" => {
                if let Some(value) = args.next() {
                    data_dir = PathBuf::from(value);
                }
            }
            "--help" | "-h" => {
                println!("帧解析实验室 (frame parsing laboratory)");
                println!("Usage: frame-lab [--addr 127.0.0.1:5211] [--data-dir frame-lab-data]");
                return ExitCode::SUCCESS;
            }
            other => {
                eprintln!("unknown argument: {}", other);
                return ExitCode::FAILURE;
            }
        }
    }

    let server = match Server::bind(&addr, &data_dir) {
        Ok(server) => server,
        Err(e) => {
            eprintln!("failed to bind {}: {}", addr, e);
            return ExitCode::FAILURE;
        }
    };

    if let Err(e) = server.run() {
        eprintln!("server error: {}", e);
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
