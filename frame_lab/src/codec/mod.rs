// Frame codec: maps every input byte to a node in a parse tree, classifies the
// result as ok / warning / incomplete / error, and provides a deterministic
// inverse encoder used by the test generator.

pub mod checksum;
pub mod encode;
pub mod parse;

pub use encode::encode;
pub use parse::parse_frame;

use crate::json::Json;

/// Classification of the whole frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Ok,
    Warning,
    Incomplete,
    Error,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Ok => "ok",
            Status::Warning => "warning",
            Status::Incomplete => "incomplete",
            Status::Error => "error",
        }
    }
    pub fn parse(s: &str) -> Status {
        match s {
            "warning" => Status::Warning,
            "incomplete" => Status::Incomplete,
            "error" => Status::Error,
            _ => Status::Ok,
        }
    }
    pub fn rank(self) -> u8 {
        match self {
            Status::Ok => 0,
            Status::Warning => 1,
            Status::Incomplete => 2,
            Status::Error => 3,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Span {
    /// Byte offset relative to the whole frame.
    pub start: usize,
    pub len: usize,
}

impl Span {
    pub fn end(&self) -> usize {
        self.start + self.len
    }
    pub fn contains(&self, off: usize) -> bool {
        off >= self.start && off < self.end()
    }
}

#[derive(Debug, Clone)]
pub struct Diagnostic {
    pub level: Status,
    pub message: String,
    pub path: String,
    pub byte: Option<usize>,
}

/// A single node in the parse tree.
#[derive(Debug, Clone)]
pub struct Node {
    pub kind: String,
    pub name: String,
    pub path: String,
    pub span: Option<Span>,
    pub value: Json,
    pub children: Vec<Node>,
    pub status: Status,
    /// Checksum cover intervals (absolute), populated after tree assembly.
    pub cover: Vec<Span>,
    /// Checksum cover specification (checksum nodes only, not serialised).
    pub cover_spec: Option<crate::spec::CoverSpec>,
    /// Checksum algorithm label (checksum nodes only).
    pub algo_label: Option<String>,
}

impl Node {
    pub fn to_json(&self) -> Json {
        let mut o = Json::obj();
        o.put("kind", Json::str(&self.kind));
        o.put("name", Json::str(&self.name));
        o.put("path", Json::str(&self.path));
        match self.span {
            Some(s) => {
                o.put("start", Json::uint(s.start as u64));
                o.put("length", Json::uint(s.len as u64));
            }
            None => {
                o.put("start", Json::Null);
                o.put("length", Json::uint(0));
            }
        }
        o.put("value", self.value.clone());
        o.put("status", Json::str(self.status.as_str()));
        o.put(
            "cover",
            Json::arr(
                self.cover
                    .iter()
                    .map(|s| {
                        let mut c = Json::obj();
                        c.put("start", Json::uint(s.start as u64));
                        c.put("length", Json::uint(s.len as u64));
                        c
                    })
                    .collect(),
            ),
        );
        o.put(
            "children",
            Json::arr(self.children.iter().map(|c| c.to_json()).collect()),
        );
        o
    }

    /// Pre-order walk, including the node itself.
    pub fn walk(&self) -> NodeWalk<'_> {
        NodeWalk { stack: vec![self] }
    }

    /// Deepest node whose span covers the offset (preferring the deepest).
    pub fn deepest_at(&self, off: usize) -> Option<&Node> {
        let mut best: Option<&Node> = None;
        for n in self.walk() {
            if n.span.map(|s| s.contains(off)).unwrap_or(false) {
                let depth = n.path.split('.').count();
                match best {
                    Some(b) if b.path.split('.').count() >= depth => {}
                    _ => best = Some(n),
                }
            }
        }
        best
    }
}

pub struct NodeWalk<'a> {
    stack: Vec<&'a Node>,
}

#[allow(dead_code)]
pub fn node_placeholder() {}
impl<'a> Iterator for NodeWalk<'a> {
    type Item = &'a Node;
    fn next(&mut self) -> Option<&'a Node> {
        let n = self.stack.pop()?;
        for c in n.children.iter().rev() {
            self.stack.push(c);
        }
        Some(n)
    }
}

#[derive(Debug, Clone)]
pub struct ParseResult {
    pub status: Status,
    pub root: Option<Node>,
    pub diagnostics: Vec<Diagnostic>,
    /// Lower bound on still-needed bytes (incomplete only).
    pub need: usize,
    pub consumed: usize,
}

impl ParseResult {
    pub fn to_json(&self) -> Json {
        let mut o = Json::obj();
        o.put("status", Json::str(self.status.as_str()));
        o.put(
            "root",
            match &self.root {
                Some(r) => r.to_json(),
                None => Json::Null,
            },
        );
        o.put(
            "diagnostics",
            Json::arr(
                self.diagnostics
                    .iter()
                    .map(|d| {
                        let mut x = Json::obj();
                        x.put("level", Json::str(d.level.as_str()));
                        x.put("message", Json::str(&d.message));
                        x.put("path", Json::str(&d.path));
                        match d.byte {
                            Some(b) => x.put("byte", Json::uint(b as u64)),
                            None => x.put("byte", Json::Null),
                        }
                        x
                    })
                    .collect(),
            ),
        );
        o.put("need", Json::uint(self.need as u64));
        o.put("consumed", Json::uint(self.consumed as u64));
        o.put("digest", Json::str(self.digest()));
        o
    }

    /// Deterministic tree/diagnostic digest used for export/import equality.
    pub fn digest(&self) -> String {
        let summary = self.summary();
        crate::hash::hex_encode(&crate::hash::sha256(summary.as_bytes()))
    }

    pub fn summary(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        parts.push(format!("status={}", self.status.as_str()));
        if let Some(root) = &self.root {
            for n in root.walk() {
                let sp = match n.span {
                    Some(s) => format!("{}+{}", s.start, s.len),
                    None => "-".to_string(),
                };
                parts.push(format!(
                    "{}|{}|{}|{}|{}",
                    n.path,
                    n.kind,
                    sp,
                    n.status.as_str(),
                    n.value.canonical()
                ));
            }
        }
        for d in &self.diagnostics {
            parts.push(format!(
                "diag|{}|{}|{}|{}",
                d.level.as_str(),
                d.path,
                d.byte.map(|b| b.to_string()).unwrap_or_else(|| "-".to_string()),
                d.message
            ));
        }
        parts.join("\n")
    }
}

pub fn hex_bytes_string(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(" ")
}
