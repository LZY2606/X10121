use frame_lab::codec::{encode, parse_frame, Status};
use frame_lab::json::{self, Json};
use frame_lab::spec::Protocol;

fn schema() -> Json {
    json::parse(
        r#"{
      "name": "demo",
      "root": "Frame",
      "max_depth": 5,
      "structs": {
        "Frame": [
          {"name": "magic", "type": "uint", "width": 2, "const": 42245},
          {"name": "version", "type": "uint", "width": 1},
          {"name": "len", "type": "uint", "width": 1},
          {"name": "payload", "type": "bytes", "length": {"field": "len"}},
          {"name": "crc", "type": "checksum", "algo": "sum8"}
        ]
      }
    }"#,
    )
    .unwrap()
}

fn main() {
    let s = schema();
    let proto = Protocol::compile(&s).unwrap();
    let value = json::parse(
        r#"{"magic": 42245, "version": 1, "len": 3, "payload": "010203", "crc": 0}"#,
    )
    .unwrap();
    let bytes = encode(&proto, &value).unwrap();
    println!("encoded: {}", frame_lab::hash::hex_encode(&bytes));

    let result = parse_frame(&proto, &bytes);
    println!("status: {}", result.status.as_str());
    println!("{}", result.root.as_ref().unwrap().to_json().pretty());

    // Truncation must be incomplete.
    let cut = &bytes[..bytes.len() - 2];
    let r2 = parse_frame(&proto, cut);
    assert_eq!(r2.status, Status::Incomplete, "truncation must be incomplete, got {:?}: {}", r2.status, r2.diagnostics[0].message);
    println!("truncated need={} path={}", r2.need, r2.diagnostics[0].path);

    // Corrupt a payload byte -> checksum error on crc.
    let mut bad = bytes.clone();
    bad[4] ^= 0xff;
    let r3 = parse_frame(&proto, &bad);
    assert_eq!(r3.status, Status::Error);
    println!("corrupt diag: {} @ {}", r3.diagnostics[0].message, r3.diagnostics[0].path);
}
