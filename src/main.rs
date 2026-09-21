use std::net::SocketAddr;

use frame_lab::server;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut addr: SocketAddr = "127.0.0.1:5211".parse().expect("默认地址解析失败");
    let mut data_dir = "frame-lab-data".to_string();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--addr" => {
                i += 1;
                addr = args
                    .get(i)
                    .expect("缺少 --addr 的值")
                    .parse()
                    .expect("无法解析监听地址，格式应为 127.0.0.1:5211");
            }
            "--data-dir" => {
                i += 1;
                data_dir = args.get(i).expect("缺少 --data-dir 的值").clone();
            }
            other => {
                eprintln!("未知参数: {}", other);
                std::process::exit(2);
            }
        }
        i += 1;
    }

    if let Err(e) = server::serve(addr, &data_dir) {
        eprintln!("服务器退出: {}", e);
        std::process::exit(1);
    }
}
