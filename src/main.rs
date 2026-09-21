use framelab::server;
use framelab::store::Store;
use std::path::PathBuf;
use std::sync::Arc;

struct Args {
    addr: String,
    data_dir: PathBuf,
}

fn parse_args() -> Args {
    let mut addr = "127.0.0.1:5211".to_string();
    let mut data_dir = PathBuf::from("frame-lab-data");
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--addr" => {
                if let Some(v) = it.next() {
                    addr = v;
                }
            }
            "--data-dir" => {
                if let Some(v) = it.next() {
                    data_dir = PathBuf::from(v);
                }
            }
            other => {
                eprintln!("忽略未知参数: {}", other);
            }
        }
    }
    Args { addr, data_dir }
}

fn main() {
    let args = parse_args();
    let store =
        Store::open(&args.data_dir).unwrap_or_else(|e| panic!("打开数据目录失败 {}: {}", args.data_dir.display(), e));
    if let Err(e) = framelab::samples::seed_demo_protocol(&store) {
        eprintln!("内置协议初始化失败: {}", e);
    }
    let store = Arc::new(store);
    if let Err(e) = server::run(&args.addr, store) {
        eprintln!("服务器退出: {}", e);
        std::process::exit(1);
    }
}
