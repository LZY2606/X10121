use frame_lab::store::Store;
use frame_lab::{demo_frame, DEMO_PROTOCOL_JSON};
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

fn main() {
    let mut addr = "127.0.0.1:5211".to_string();
    let mut data_dir = PathBuf::from("data");
    let args: Vec<String> = std::env::args().collect();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--addr" if i + 1 < args.len() => {
                addr = args[i + 1].clone();
                i += 2;
            }
            "--data-dir" if i + 1 < args.len() => {
                data_dir = PathBuf::from(&args[i + 1]);
                i += 2;
            }
            other => {
                eprintln!("unknown argument: {other}");
                eprintln!("usage: frame_lab [--addr 127.0.0.1:5211] [--data-dir data]");
                std::process::exit(2);
            }
        }
    }

    let mut store = Store::open(&data_dir).unwrap_or_else(|e| {
        eprintln!("failed to open store at {}: {e}", data_dir.display());
        std::process::exit(1);
    });
    // 首次启动时播种演示协议、样例 blob 与一个会话，便于直接体验。
    if store.protocols.is_empty() {
        let content: serde_json::Value =
            serde_json::from_str(DEMO_PROTOCOL_JSON).expect("demo protocol is valid JSON");
        let pv = store.add_protocol("demo-frame", content).expect("seed protocol");
        let (blob_id, _) = store.add_blob(&demo_frame());
        let session = store.create_session(&pv.id, &blob_id).expect("seed session");
        println!("seeded demo protocol {} and session {}", pv.id, session.id);
    }

    let listener = TcpListener::bind(&addr).unwrap_or_else(|e| {
        eprintln!("failed to bind {addr}: {e}");
        std::process::exit(1);
    });
    frame_lab::server::run(listener, Arc::new(Mutex::new(store))).unwrap();
}
