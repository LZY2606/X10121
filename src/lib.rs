//! Frame parsing laboratory core library: protocol descriptions, parser,
//! encoder, content-addressed storage and the embedded HTTP service.

pub mod encoder;
pub mod hash;
pub mod hex;
pub mod parser;
pub mod server;
pub mod spec;
pub mod store;

pub use parser::{parse as parse_bytes, ParseResult};
pub use spec::{RawSpec, Spec};
