//! 编译后的协议模型（不可变）。解析器与编码器只依赖它。

/// 表达式：字面量、字段引用、字段结束偏移、二元运算、括号。
#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    Lit(u64),
    /// 同结构内字段名引用
    Var(String),
    /// 字段结束偏移（绝对偏移），`@name.end`
    EndOf(String),
    /// 字段起始偏移（绝对偏移），`@name`
    StartOf(String),
    Bin(Box<Expr>, BinOp, Box<Expr>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinOp {
    Add,
    Sub,
    Mul,
    Div,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    And,
    Or,
}

impl BinOp {
    pub fn symbol(self) -> &'static str {
        match self {
            BinOp::Add => "+",
            BinOp::Sub => "-",
            BinOp::Mul => "*",
            BinOp::Div => "/",
            BinOp::Eq => "==",
            BinOp::Ne => "!=",
            BinOp::Lt => "<",
            BinOp::Le => "<=",
            BinOp::Gt => ">",
            BinOp::Ge => ">=",
            BinOp::And => "&&",
            BinOp::Or => "||",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckAlgo {
    Sum8,
    Xor8,
    Sum16Be,
}

/// 校验区间边界：字段名 / 字段结束 / 常量绝对偏移。
#[derive(Debug, Clone, PartialEq)]
pub enum RangeBound {
    StartOf(String),
    EndOf(String),
    StructStart,
    StructEnd,
    Const(u64),
}

#[derive(Debug, Clone, PartialEq)]
pub struct CheckSpec {
    pub algo: CheckAlgo,
    pub from: Option<RangeBound>,
    pub to: Option<RangeBound>,
    /// 校验字段自身是否从覆盖区间排除。
    pub skip_self: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntKind {
    U8,
    U16Be,
    U16Le,
    U24Be,
    U32Be,
    U32Le,
}

impl IntKind {
    pub fn width(self) -> usize {
        match self {
            IntKind::U8 => 1,
            IntKind::U16Be | IntKind::U16Le => 2,
            IntKind::U24Be => 3,
            IntKind::U32Be | IntKind::U32Le => 4,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum RepeatBody {
    StructRef(String),
    StructDef(StructDef),
    Raw,
}

#[derive(Debug, Clone, PartialEq)]
pub enum FieldKind {
    /// 定长无符号整数
    Int(IntKind),
    /// 定长原始字节 `bytes N`
    FixedBytes(usize),
    /// 长度表达式决定的原始字节 `bytes <expr>`
    VarBytes(Expr),
    /// 长度表达式决定的内联结构（定界）
    InlineStruct(StructDef),
    /// 引用命名结构。None = 父结构剩余字节（只能是最后一个字段）
    StructRef(String, Option<Expr>),
    /// 重复字段：计数表达式 + 体
    Repeat(Expr, RepeatBody),
    /// 校验和
    Checksum(CheckSpec),
    /// 编译期/运行期常量断言
    Assert(Expr),
}

#[derive(Debug, Clone, PartialEq)]
pub struct Field {
    pub name: String,
    pub kind: FieldKind,
    /// 条件：表达式为假时该字段（及其字节）不存在。
    pub when: Option<Expr>,
    /// 原始声明行号（1 起），用于诊断。
    pub line: usize,
}

impl Field {
    pub fn is_int(&self) -> bool {
        matches!(self.kind, FieldKind::Int(_))
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct StructDef {
    pub name: Option<String>,
    pub fields: Vec<Field>,
}

#[derive(Debug, Clone)]
pub struct Protocol {
    pub name: String,
    pub root: String,
    pub max_depth: usize,
    pub structs: Vec<StructDef>,
}

impl Protocol {
    pub fn find(&self, name: &str) -> Option<&StructDef> {
        self.structs.iter().find(|s| s.name.as_deref() == Some(name))
    }
}

/// 字段是否消耗“结构剩余全部字节”。
pub fn is_rest(kind: &FieldKind) -> bool {
    match kind {
        FieldKind::StructRef(_, None) => true,
        _ => false,
    }
}
