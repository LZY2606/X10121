//! 启动器：frame_lab --addr 127.0.0.1:5211 [--data-dir DIR]
use frame_lab::api::Api;
use frame_lab::server;
use frame_lab::storage::Store;
use std::sync::Arc;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut addr = "127.0.0.1:5211".to_string();
    let mut data_dir = "frame_lab_data".to_string();
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
                    data_dir = v.clone();
                }
            }
            other => {
                eprintln!("未知参数：{other}");
                eprintln!("用法：frame_lab --addr 127.0.0.1:5211 [--data-dir DIR]");
                std::process::exit(2);
            }
        }
        i += 1;
    }

    let store = Store::open(&data_dir).unwrap_or_else(|e| {
        eprintln!("初始化仓库目录 {data_dir} 失败：{e}");
        std::process::exit(1);
    });
    seed_demo(&store);
    let api = Arc::new(Api::new(store));
    server::serve(&addr, api).unwrap_or_else(|e| {
        eprintln!("{e}");
        std::process::exit(1);
    });
}

fn seed_demo(store: &Store) {
    let specs = store.list_protocols().unwrap_or_default();
    let demo = frame_lab::demo::demo_spec_json();
    let digest = frame_lab::storage::spec_digest(&demo);
    for s in &specs {
        if let Ok(p) = store.load_protocol(&s.id) {
            if p.revisions.iter().any(|r| r.digest == digest) {
                return;
            }
        }
    }
    let _ = store.create_protocol(frame_lab::demo::DEMO_NAME, &demo, "内置演示协议");
}
