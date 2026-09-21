use framelab::*;

#[test]
fn smoke_simple_packet() {
    let p = compile_protocol(seeds::SIMPLE_PACKET).unwrap();
    let values = json::parse(r#"{
        "magic": 4660,
        "ptype": 1,
        "payload": "aabbcc"
    }"#).unwrap();
    let frame = encoder::encode(&p, &values).unwrap();
    println!("frame = {}", hex::encode(&frame));
    let out = parse_bytes(&p, &frame);
    println!("status = {}", out.status);
    println!("{}", out.to_json().pretty());
    assert_eq!(out.status, "complete");
}
