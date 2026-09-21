use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let mut addr = "127.0.0.1:5211".to_string();
    let mut data_dir = PathBuf::from("frame-lab-data");

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--addr" => {
                i += 1;
                if let Some(v) = args.get(i) {
                    addr = v.clone();
                }
            }
            "--data-dir" => {
                i += 1;
                if let Some(v) = args.get(i) {
                    data_dir = PathBuf::from(v);
                }
            }
            "-h" | "--help" => {
                println!("用法: frame_lab [--addr 127.0.0.1:5211] [--data-dir frame-lab-data]");
                return ExitCode::SUCCESS;
            }
            other => {
                eprintln!("未知参数: {}", other);
                return ExitCode::FAILURE;
            }
        }
        i += 1;
    }

    match frame_lab::server::run(&addr, &data_dir) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("服务器启动失败: {e}");
            ExitCode::FAILURE
        }
    }
}
