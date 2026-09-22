//! 内置演示协议。演示所有能力：
//! - 定长整数（含枚举、常量、字节序）
//! - 由前置字段决定长度的 payload（且不能越过父结构边界）
//! - 带条件的子结构（kind=2 时出现）
//! - 递归结构（node，可配置深度上限）
//! - 校验和覆盖区间，skip_self 跳过自身字段
//! - length_ref 定义 body / frame 的硬边界
use crate::json::Json;

pub const DEMO_NAME: &str = "演示设备帧 DemoFrame v1";

pub fn demo_spec_json() -> Json {
    Json::parse(include_str!("static/demo_spec.json")).expect("内置演示协议 JSON 必须合法")
}

/// 用编码器生成一帧合法演示样本（含递归 TLV 节点），返回十六进制。
pub fn demo_sample_hex() -> String {
    use crate::encoder;
    let spec = crate::spec::Spec::from_json(&demo_spec_json()).unwrap();
    let values = Json::parse(
        r#"{
          "soi": 170,
          "frame_len": 19,
          "kind": 2,
          "seq": 7,
          "body": {
            "clen": 12,
            "payload": "010203",
            "tail": { "marker": 205 },
            "node": {
              "ntype": 1,
              "nlen": 2,
              "nval": "ab cd",
              "child": {
                "ntype": 9,
                "nlen": 0,
                "nval": ""
              }
            }
          }
        }"#,
    )
    .unwrap();
    let bytes = encoder::encode(&spec, &values).unwrap();
    assert!(!bytes.is_empty(), "演示样本编码不应为空");
    crate::hexutil::encode_hex(&bytes)
}
