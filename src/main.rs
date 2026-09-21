//! 帧解析实验室启动入口。

use std::path::PathBuf;
use std::sync::Arc;

use frame_lab::web::{self, AppState};

struct Args {
    addr: String,
    data_dir: PathBuf,
}

fn parse_args() -> Result<Args, String> {
    let mut addr = "127.0.0.1:5211".to_string();
    let mut data_dir = PathBuf::from("data");
    let mut iter = std::env::args().skip(1);
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--addr" => {
                addr = iter
                    .next()
                    .ok_or_else(|| "--addr 需要一个地址参数，例如 127.0.0.1:5211".to_string())?;
            }
            "--data-dir" => {
                data_dir = PathBuf::from(
                    iter.next()
                        .ok_or_else(|| "--data-dir 需要一个目录参数".to_string())?,
                );
            }
            "-h" | "--help" => {
                println!("用法：frame-lab --addr 127.0.0.1:5211 [--data-dir data]");
                std::process::exit(0);
            }
            other => return Err(format!("未知参数 `{other}`（支持 --addr / --data-dir）")),
        }
    }
    Ok(Args { addr, data_dir })
}

fn main() {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("参数错误：{e}");
            std::process::exit(2);
        }
    };
    let state = match AppState::open(args.data_dir) {
        Ok(s) => Arc::new(s),
        Err(e) => {
            eprintln!("初始化仓库目录失败：{e}");
            std::process::exit(1);
        }
    };
    if let Err(e) = web::serve(&args.addr, state) {
        eprintln!("HTTP 服务退出：{e}");
        std::process::exit(1);
    }
}
