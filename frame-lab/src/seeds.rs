//! 内置示例协议描述。

pub const SIMPLE_PACKET: &str = "\
# 简单分帧：魔数 + 类型 + 长度 + payload + 校验和
protocol simple_packet
root Packet
max_depth 8

struct Packet {
    u16be magic
    u8 ptype
    u16be length
    bytes length payload
    checksum cs : sum8 from start to @cs
}
";

pub const TLV_RECURSIVE: &str = "\
# 递归 TLV：size 决定单个 Node 的内容区间，重复子节点
protocol tlv_recursive
root Root
max_depth 6

struct Root {
    u8 count
    repeat entries {
        Node<size>
    } count count
}

struct Node {
    u8 kind
    u8 size
    u8 child_count
    bytes size - 2 data
    repeat children {
        Node<size>
    } count child_count
}
";

pub const HEADER_ONLY: &str = "\
# 定长头 + 条件字段 + 常量断言
protocol header_only
root Header
max_depth 4

struct Header {
    u8 version
    u8 flags
    u16be length
    bytes length body
    assert version == 1
    checksum xor : xor8 from start
}
";

pub fn all() -> Vec<(&'static str, &'static str)> {
    vec![
        ("simple_packet", SIMPLE_PACKET),
        ("tlv_recursive", TLV_RECURSIVE),
        ("header_only", HEADER_ONLY)]
}
