//! 帧解析实验室可执行入口。
//!
//! 用法：frame-lab --addr 127.0.0.1:5211 [--data ./frame-lab-data]

use framelab::server;
use framelab::store::LabStore;
use std::sync::Arc;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut addr = "127.0.0.1:5211".to_string();
    let mut data = "frame-lab-data".to_string();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--addr" => {
                i += 1;
                addr = args.get(i).cloned().expect("--addr 需要地址参数");
            }
            "--data" => {
                i += 1;
                data = args.get(i).cloned().expect("--data 需要目录参数");
            }
            "-h" | "--help" => {
                println!("用法: frame-lab --addr 127.0.0.1:5211 [--data ./frame-lab-data]");
                return;
            }
            other => {
                eprintln!("未知参数 {}", other);
                std::process::exit(2);
            }
        }
        i += 1;
    }

    let store = match LabStore::open(&data) {
        Ok(s) => Arc::new(s),
        Err(e) => {
            eprintln!("初始化数据目录 {} 失败：{}", data, e);
            std::process::exit(1);
        }
    };

    if let Err(e) = server::serve(store, &addr) {
        eprintln!("服务器退出：{}", e);
        std::process::exit(1);
    }
}
