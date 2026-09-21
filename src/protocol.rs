//! 协议描述 DSL：以 JSON 表达的帧结构定义。
//!
//! 节点类型：
//! - `uint`      定长整数（1..=8 字节，可指定大小端）
//! - `bytes`     定长原始字节
//! - `var_bytes` 变长字段，长度取自先前兄弟字段 `len_from`，可选 `max` 上限
//! - `seq`       子结构；可选 `len_from` 使其成为长度受限的窗口
//! - `if`        条件子结构，条件引用先前兄弟整数字段
//! - `checksum`  校验和，`cover` 指定覆盖区间（可跳过自身字段）
use serde::Deserialize;

fn default_max_depth() -> usize {
    16
}

#[derive(Debug, Clone, Deserialize)]
pub struct Protocol {
    #[serde(default)]
    pub name: Option<String>,
    /// 递归（嵌套）结构深度上限，可在协议描述中配置。
    #[serde(default = "default_max_depth")]
    pub max_depth: usize,
    pub root: Node,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Node {
    Uint {
        name: String,
        size: usize,
        #[serde(default)]
        endian: Endian,
    },
    Bytes {
        name: String,
        size: usize,
    },
    VarBytes {
        name: String,
        len_from: String,
        #[serde(default)]
        max: Option<usize>,
    },
    Seq {
        name: String,
        #[serde(default)]
        len_from: Option<String>,
        children: Vec<Node>,
    },
    If {
        name: String,
        cond: Cond,
        then: Box<Node>,
    },
    Checksum {
        name: String,
        size: usize,
        #[serde(default)]
        endian: Endian,
        algo: Algo,
        #[serde(default)]
        cover: Option<Cover>,
        #[serde(default)]
        skip_self: bool,
    },
}

impl Node {
    pub fn name(&self) -> &str {
        match self {
            Node::Uint { name, .. }
            | Node::Bytes { name, .. }
            | Node::VarBytes { name, .. }
            | Node::Seq { name, .. }
            | Node::If { name, .. }
            | Node::Checksum { name, .. } => name,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Cond {
    pub field: String,
    pub op: CmpOp,
    pub value: u64,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CmpOp {
    Eq,
    Ne,
    Gt,
    Gte,
    Lt,
    Lte,
}

impl CmpOp {
    pub fn apply(self, lhs: u64, rhs: u64) -> bool {
        match self {
            CmpOp::Eq => lhs == rhs,
            CmpOp::Ne => lhs != rhs,
            CmpOp::Gt => lhs > rhs,
            CmpOp::Gte => lhs >= rhs,
            CmpOp::Lt => lhs < rhs,
            CmpOp::Lte => lhs <= rhs,
        }
    }
}

/// 覆盖区间：from/to 均为先前兄弟字段名；to 还支持 "@self"（校验和自身起点）
/// 与 "@end"（父结构窗口末尾）。缺省 from = 首个兄弟字段，to = 校验和字段起点。
#[derive(Debug, Clone, Deserialize)]
pub struct Cover {
    #[serde(default)]
    pub from: Option<String>,
    #[serde(default)]
    pub to: Option<String>,
}

#[derive(Debug, Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Endian {
    #[default]
    Big,
    Little,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Algo {
    Sum8,
    Sum16,
    Xor8,
}

impl Algo {
    pub fn compute(self, data: &[u8]) -> u64 {
        match self {
            Algo::Sum8 => data.iter().map(|b| *b as u64).sum::<u64>() & 0xff,
            Algo::Sum16 => data.iter().map(|b| *b as u64).sum::<u64>() & 0xffff,
            Algo::Xor8 => data.iter().fold(0u64, |acc, b| acc ^ (*b as u64)),
        }
    }
}
