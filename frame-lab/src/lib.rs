//! 帧解析实验室核心库：协议 DSL、解析/编码引擎、会话存储。

pub mod dsl_check;
pub mod dsl_lex;
pub mod dsl_parse;
pub mod encoder;
pub mod eval;
pub mod hex;
pub mod json;
pub mod model;
pub mod parser;
pub mod seeds;
pub mod server;
pub mod sha256;
pub mod store;

pub use json::Json;
pub use model::Protocol;
pub use parser::ParseOut;

/// 从 DSL 源文本编译协议（解析 + 语义检查）。
pub fn compile_protocol(src: &str) -> Result<Protocol, String> {
    dsl_check::compile(src)
}

/// 解析十六进制输入。
pub fn parse_hex(input: &str) -> Result<Vec<u8>, String> {
    hex::decode(input)
}

/// 解析原始字节。
pub fn parse_bytes(protocol: &Protocol, data: &[u8]) -> ParseOut {
    parser::parse(protocol, data)
}
