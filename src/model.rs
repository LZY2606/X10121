//! 解析报告的数据模型、JSON 序列化与确定性摘要。
use crate::json::Json;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Ok,
    Incomplete,
    Violation,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Ok => "ok",
            Status::Incomplete => "incomplete",
            Status::Violation => "violation",
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Status::Ok => "成功",
            Status::Incomplete => "输入尚未完整",
            Status::Violation => "输入违反协议",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Warning {
    pub path: String,
    pub code: String,
    pub message: String,
    pub offset: Option<usize>,
}

#[derive(Debug, Clone)]
pub struct ErrorInfo {
    pub code: String,
    pub kind: &'static str, // incomplete | violation
    pub message: String,
    /// 最深字段路径
    pub path: String,
    /// 字节偏移
    pub offset: usize,
    /// incomplete：至少仍需多少字节（下界）
    pub need: Option<usize>,
}

#[derive(Debug, Clone, Default)]
pub struct ParseNode {
    pub name: String,
    pub path: String,
    pub kind: &'static str, // int | bytes | struct | array
    pub dtype: String,
    pub value: Option<String>,
    pub start: usize,
    pub end: usize,
    pub children: Vec<ParseNode>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ParseReport {
    pub status: Status,
    pub tree: Option<ParseNode>,
    pub error: Option<ErrorInfo>,
    pub warnings: Vec<Warning>,
    pub input_len: usize,
    pub consumed: usize,
}

impl ParseNode {
    fn to_json(&self) -> Json {
        let mut o = Json::obj();
        o.put("name", Json::Str(self.name.clone()));
        o.put("path", Json::Str(self.path.clone()));
        o.put("kind", Json::Str(self.kind.to_string()));
        o.put("dtype", Json::Str(self.dtype.clone()));
        match &self.value {
            Some(v) => o.put("value", Json::Str(v.clone())),
            None => o.put("value", Json::Null),
        }
        o.put("start", Json::Int(self.start as i64));
        o.put("end", Json::Int(self.end as i64));
        o.put(
            "children",
            Json::Arr(self.children.iter().map(|c| c.to_json()).collect()),
        );
        o.put(
            "warnings",
            Json::Arr(self.warnings.iter().map(|w| Json::Str(w.clone())).collect()),
        );
        o
    }

    /// 解析树摘要（规范化 JSON）：仅包含结构性信息。
    pub fn summary_json(&self) -> Json {
        let mut o = Json::obj();
        o.put("path", Json::Str(self.path.clone()));
        o.put("kind", Json::Str(self.kind.to_string()));
        o.put("dtype", Json::Str(self.dtype.clone()));
        o.put("start", Json::Int(self.start as i64));
        o.put("end", Json::Int(self.end as i64));
        o.put(
            "value",
            Json::Str(self.value.clone().unwrap_or_default()),
        );
        o.put(
            "children",
            Json::Arr(self.children.iter().map(|c| c.summary_json()).collect()),
        );
        o
    }
}

impl Warning {
    fn to_json(&self) -> Json {
        Json::obj()
            .with("path", Json::Str(self.path.clone()))
            .with("code", Json::Str(self.code.clone()))
            .with("message", Json::Str(self.message.clone()))
            .with(
                "offset",
                self.offset.map(|n| Json::Int(n as i64)).unwrap_or(Json::Null),
            )
    }
}

impl ErrorInfo {
    fn to_json(&self) -> Json {
        Json::obj()
            .with("code", Json::Str(self.code.clone()))
            .with("kind", Json::Str(self.kind.to_string()))
            .with("message", Json::Str(self.message.clone()))
            .with("path", Json::Str(self.path.clone()))
            .with("offset", Json::Int(self.offset as i64))
            .with(
                "need",
                self.need.map(|n| Json::Int(n as i64)).unwrap_or(Json::Null),
            )
    }
}

impl ParseReport {
    pub fn to_json(&self) -> Json {
        let mut o = Json::obj();
        o.put("status", Json::Str(self.status.as_str().to_string()));
        o.put("status_label", Json::Str(self.status.label().to_string()));
        match &self.tree {
            Some(t) => o.put("tree", t.to_json()),
            None => o.put("tree", Json::Null),
        }
        match &self.error {
            Some(e) => o.put("error", e.to_json()),
            None => o.put("error", Json::Null),
        }
        o.put(
            "warnings",
            Json::Arr(self.warnings.iter().map(|w| w.to_json()).collect()),
        );
        o.put("input_len", Json::Int(self.input_len as i64));
        o.put("consumed", Json::Int(self.consumed as i64));
        o.put("tree_digest", Json::Str(self.tree_digest()));
        o
    }

    pub fn tree_summary(&self) -> Json {
        match &self.tree {
            Some(t) => t.summary_json(),
            None => Json::Null,
        }
    }

    /// 解析树摘要的 SHA-256（十六进制）。
    pub fn tree_digest(&self) -> String {
        match &self.tree {
            Some(t) => crate::hash::hex_lower(&crate::hash::sha256(t.summary_json().dump().as_bytes())),
            None => crate::hash::hex_lower(&crate::hash::sha256(b"no-tree")),
        }
    }

    /// 完整诊断摘要：状态、错误、警告、解析树摘要一并哈希。
    pub fn report_digest(&self) -> String {
        let mut o = Json::obj();
        o.put("status", Json::Str(self.status.as_str().to_string()));
        o.put("error", self.error.as_ref().map(|e| e.to_json()).unwrap_or(Json::Null));
        o.put(
            "warnings",
            Json::Arr(self.warnings.iter().map(|w| w.to_json()).collect()),
        );
        o.put("tree", self.tree_summary());
        o.put("input_len", Json::Int(self.input_len as i64));
        o.put("consumed", Json::Int(self.consumed as i64));
        crate::hash::hex_lower(&crate::hash::sha256(o.dump().as_bytes()))
    }
}
