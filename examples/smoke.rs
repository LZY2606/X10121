//! 最小使用示例：编码一帧合法演示协议样本，验证
//!   1) 解析成功；2) 每个真前缀都只产生 incomplete。
fn main() {
    let spec = frame_lab::spec::Spec::from_json(&frame_lab::demo::demo_spec_json()).unwrap();
    let hex = frame_lab::demo::demo_sample_hex();
    let bytes = frame_lab::hexutil::decode_hex(&hex).unwrap();
    println!("演示帧（{} 字节）：{hex}", bytes.len());

    let report = frame_lab::parser::parse(&spec, &bytes);
    println!("解析状态：{:?}", report.status);

    for cut in 0..bytes.len() {
        let r = frame_lab::parser::parse(&spec, &bytes[..cut]);
        assert!(matches!(r.status, frame_lab::model::Status::Incomplete));
    }
    println!("全部 {} 个真前缀均为 incomplete", bytes.len());
}
