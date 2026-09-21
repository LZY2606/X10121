use frame_lab::{error::LabResult, server};
use std::path::PathBuf;

fn main() -> LabResult<()> {
    let args: Vec<String> = std::env::args().collect();
    let mut addr = "127.0.0.1:5211".to_string();
    let mut data_dir = PathBuf::from("frame-lab-data");
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--addr" => {
                i += 1;
                addr = args
                    .get(i)
                    .cloned()
                    .ok_or_else(|| frame_lab::error::LabError::new("--addr 需要参数"))?;
            }
            "--data-dir" => {
                i += 1;
                data_dir = PathBuf::from(
                    args.get(i)
                        .ok_or_else(|| frame_lab::error::LabError::new("--data-dir 需要参数"))?,
                );
            }
            other => {
                return Err(frame_lab::error::LabError::new(format!(
                    "未知参数 {other}（支持 --addr、--data-dir）"
                )));
            }
        }
        i += 1;
    }
    server::run(&addr, &data_dir)
}
