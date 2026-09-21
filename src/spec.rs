//! 小型协议描述：编译 JSON 描述成不可变的协议版本。
//!
//! 支持的字段类型：
//! - 定长整数 u8/u16/u24/u32（及有符号变体），可带 `expect` 常量断言
//! - 定长/变长 `bytes`、`string`，长度可引用同结构中更早出现的整数字段
//! - 有界（length）或无界（沿用到父结构末尾）的子结构 `struct`
//! - 按 count 展开的 `array`，以及吃光剩余字节的 `rest`
//! - `checksum`：区间端点可为字段名 / soi / eoi，默认跳过自身字段

use std::collections::{BTreeMap, BTreeSet};

use crate::json::Json;

pub const DEFAULT_MAX_DEPTH: u32 = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endian {
    Big,
    Little,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Error,
    Warn,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LengthExpr {
    Fixed(i64),
    Field {
        name: String,
        scale: i64,
        offset: i64,
    },
}

impl LengthExpr {
    pub fn to_json(&self) -> Json {
        match self {
            LengthExpr::Fixed(n) => Json::Int(*n),
            LengthExpr::Field { name, scale, offset } => {
                let mut o = Json::obj();
                o.insert("field", Json::from_str_value(name.clone()));
                if *scale != 1 {
                    o.insert("scale", Json::Int(*scale));
                }
                if *offset != 0 {
                    o.insert("offset", Json::Int(*offset));
                }
                o
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WhenOp {
    Eq,
    Ne,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct When {
    pub field: String,
    pub op: WhenOp,
    pub value: i64,
}

impl When {
    pub fn holds(&self, known: &BTreeMap<String, i64>) -> bool {
        match known.get(&self.field) {
            Some(v) => match self.op {
                WhenOp::Eq => *v == self.value,
                WhenOp::Ne => *v != self.value,
            },
            None => false,
        }
    }

    fn to_json(&self) -> Json {
        let mut o = Json::obj();
        o.insert("field", Json::from_str_value(self.field.clone()));
        match self.op {
            WhenOp::Eq => o.insert("eq", Json::Int(self.value)),
            WhenOp::Ne => o.insert("ne", Json::Int(self.value)),
        }
        o
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChecksumAlg {
    Sum8,
    Xor8,
    Sum16Be,
}

impl ChecksumAlg {
    pub fn width(&self) -> usize {
        match self {
            ChecksumAlg::Sum8 | ChecksumAlg::Xor8 => 1,
            ChecksumAlg::Sum16Be => 2,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            ChecksumAlg::Sum8 => "sum8",
            ChecksumAlg::Xor8 => "xor8",
            ChecksumAlg::Sum16Be => "sum16be",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BoundaryRef {
    Start,
    End,
    Field(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldKind {
    Int {
        width: u8,
        signed: bool,
        endian: Endian,
        expect: Option<i64>,
    },
    Bytes {
        length: LengthExpr,
    },
    String_ {
        length: LengthExpr,
    },
    Struct {
        struct_name: String,
        length: Option<LengthExpr>,
        max_depth: u32,
    },
    Array {
        item: Box<FieldDef>,
        count: LengthExpr,
    },
    Rest,
    Checksum {
        alg: ChecksumAlg,
        from: BoundaryRef,
        to: BoundaryRef,
        skip_self: bool,
        severity: Severity,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldDef {
    pub name: String,
    pub kind: FieldKind,
    pub when: Option<When>,
}

#[derive(Debug, Clone)]
pub struct StructDef {
    pub name: String,
    pub fields: Vec<FieldDef>,
}

#[derive(Debug, Clone)]
pub struct Protocol {
    pub name: String,
    pub description: String,
    pub root: String,
    pub structs: BTreeMap<String, StructDef>,
}

#[derive(Debug, Clone)]
pub struct CompileError {
    pub path: String,
    pub message: String,
}

impl CompileError {
    pub fn new(path: impl Into<String>, message: impl Into<String>) -> Self {
        CompileError {
            path: path.into(),
            message: message.into(),
        }
    }
}

pub fn compile(text: &str) -> Result<Protocol, Vec<CompileError>> {
    let json = match crate::json::parse(text) {
        Ok(j) => j,
        Err(e) => {
            return Err(vec![CompileError::new(
                "root",
                format!("协议 JSON 无法解析：{e}"),
            )])
        }
    };
    if json.as_object().is_none() {
        return Err(vec![CompileError::new("root", "协议描述必须是 JSON 对象")]);
    }

    let mut errors = Vec::new();
    let name = require_string(&json, "name", &mut errors);
    let root = require_string(&json, "root", &mut errors);
    let description = json
        .get("description")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let mut structs = BTreeMap::new();
    match json.get("structs") {
        Some(Json::Object(map)) => {
            for (sname, sdef) in map {
                let st = compile_struct(sname, sdef, &mut errors);
                if let Some(st) = st {
                    if structs.insert(sname.clone(), st).is_some() {
                        errors.push(CompileError::new(
                            format!("structs.{sname}"),
                            "结构名重复",
                        ));
                    }
                }
            }
        }
        Some(_) => errors.push(CompileError::new("structs", "必须是结构名到定义的对象")),
        None => errors.push(CompileError::new("structs", "缺少 structs 声明")),
    }

    if name.is_some() {
        if structs.is_empty() {
            errors.push(CompileError::new("structs", "协议至少需要声明一个结构"));
        }
        if let Some(root) = &root {
            if !structs.contains_key(root) {
                errors.push(CompileError::new("root", format!("根结构 `{root}` 未在 structs 中声明")));
            }
        }
        validate_protocol(
            name.as_deref().unwrap_or(""),
            root.as_deref().unwrap_or(""),
            &structs,
            &mut errors,
        );
    }

    if !errors.is_empty() {
        return Err(errors);
    }
    Ok(Protocol {
        name: name.unwrap_or_default(),
        description,
        root: root.unwrap_or_default(),
        structs,
    })
}

fn require_string(json: &Json, key: &str, errors: &mut Vec<CompileError>) -> Option<String> {
    match json.get(key).and_then(|v| v.as_str()) {
        Some(s) if !s.is_empty() => Some(s.to_string()),
        _ => {
            errors.push(CompileError::new(key, format!("缺少非空字符串字段 `{key}`")));
            None
        }
    }
}

fn compile_struct(
    sname: &str,
    sdef: &Json,
    errors: &mut Vec<CompileError>,
) -> Option<StructDef> {
    let base = format!("structs.{sname}");
    let fields_json = sdef.get("fields").and_then(|v| v.as_array());
    let fields_json = match fields_json {
        Some(f) => f,
        None => {
            errors.push(CompileError::new(base, "`fields` 必须是非空数组"));
            return None;
        }
    };
    if fields_json.is_empty() {
        errors.push(CompileError::new(format!("{base}.fields"), "结构至少包含一个字段"));
        return None;
    }
    let mut fields = Vec::new();
    let mut seen = BTreeSet::new();
    for (i, fdef) in fields_json.iter().enumerate() {
        let fpath = format!("{base}.fields[{i}]");
        let field = compile_field(fdef, &fpath, errors);
        if let Some(field) = field {
            if !seen.insert(field.name.clone()) {
                errors.push(CompileError::new(
                    format!("{fpath}.name"),
                    format!("字段名 `{}` 在同一结构中重复", field.name),
                ));
            }
            fields.push(field);
        }
    }
    if fields.is_empty() {
        return None;
    }
    Some(StructDef {
        name: sname.to_string(),
        fields,
    })
}

fn compile_field(fdef: &Json, fpath: &str, errors: &mut Vec<CompileError>) -> Option<FieldDef> {
    let name = match fdef.get("name").and_then(|v| v.as_str()) {
        Some(n) if !n.is_empty() => n.to_string(),
        _ => {
            errors.push(CompileError::new(fpath, "字段缺少非空 `name`"));
            return None;
        }
    };
    let ftype = match fdef.get("type").and_then(|v| v.as_str()) {
        Some(t) => t.to_string(),
        None => {
            errors.push(CompileError::new(format!("{fpath}.type"), "字段缺少 `type`"));
            return None;
        }
    };
    let when = match fdef.get("when") {
        Some(w) => match compile_when(w) {
            Ok(w) => Some(w),
            Err(msg) => {
                errors.push(CompileError::new(format!("{fpath}.when"), msg));
                None
            }
        },
        None => None,
    };
    let kind = match ftype.as_str() {
        "int" => compile_int(fdef, fpath, errors)?,
        "bytes" => {
            let length = compile_length(fdef, fpath, errors)?;
            FieldKind::Bytes { length }
        }
        "string" => {
            let length = compile_length(fdef, fpath, errors)?;
            FieldKind::String_ { length }
        }
        "struct" => compile_struct_field(fdef, fpath, errors)?,
        "array" => compile_array(fdef, fpath, errors)?,
        "rest" => FieldKind::Rest,
        "checksum" => compile_checksum(fdef, fpath, errors)?,
        other => {
            errors.push(CompileError::new(
                format!("{fpath}.type"),
                format!("未知字段类型 `{other}`"),
            ));
            return None;
        }
    };
    Some(FieldDef { name, kind, when })
}

fn compile_int(fdef: &Json, fpath: &str, errors: &mut Vec<CompileError>) -> Option<FieldKind> {
    let width = match fdef.get("width").and_then(|v| v.as_i64()) {
        Some(1) | Some(2) | Some(3) | Some(4) => fdef.get("width").unwrap().as_i64().unwrap() as u8,
        _ => {
            errors.push(CompileError::new(
                format!("{fpath}.width"),
                "int 的 width 必须是 1、2、3、4（字节）",
            ));
            return None;
        }
    };
    let endian = match fdef
        .get("endian")
        .and_then(|v| v.as_str())
        .unwrap_or("big")
    {
        "big" | "be" => Endian::Big,
        "little" | "le" => Endian::Little,
        other => {
            errors.push(CompileError::new(
                format!("{fpath}.endian"),
                format!("端序只能是 big/little，收到 `{other}`"),
            ));
            return None;
        }
    };
    if width == 1 && fdef.get("endian").is_some() {
        errors.push(CompileError::new(
            format!("{fpath}.endian"),
            "单字节整数不应声明 endian",
        ));
        return None;
    }
    let signed = fdef.get("signed").and_then(|v| v.as_bool()).unwrap_or(false);
    let expect = match fdef.get("expect") {
        Some(Json::Null) | None => None,
        Some(v) => match v.as_i64() {
            Some(n) => {
                let (min, max) = int_range(width, signed);
                if n < min || n > max {
                    errors.push(CompileError::new(
                        format!("{fpath}.expect"),
                        format!("常量断言 {n} 超出 {width} 字节整数范围 [{min}, {max}]"),
                    ));
                    return None;
                }
                Some(n)
            }
            None => {
                errors.push(CompileError::new(
                    format!("{fpath}.expect"),
                    "expect 必须是整数或 null",
                ));
                return None;
            }
        },
    };
    Some(FieldKind::Int {
        width,
        signed,
        endian,
        expect,
    })
}

pub fn int_range(width: u8, signed: bool) -> (i64, i64) {
    let bits = (width as u32) * 8;
    if signed {
        (-(1i64 << (bits - 1)), (1i64 << (bits - 1)) - 1)
    } else {
        let max = if bits >= 64 { i64::MAX } else { (1i64 << bits) - 1 };
        (0, max)
    }
}

fn compile_length(fdef: &Json, fpath: &str, errors: &mut Vec<CompileError>) -> Option<LengthExpr> {
    match fdef.get("length") {
        Some(Json::Int(n)) => {
            if *n < 0 {
                errors.push(CompileError::new(
                    format!("{fpath}.length"),
                    "定长不能为负数",
                ));
                return None;
            }
            Some(LengthExpr::Fixed(*n))
        }
        Some(Json::Object(_)) => {
            let expr = fdef.get("length").unwrap();
            let field = match expr.get("field").and_then(|v| v.as_str()) {
                Some(f) => f.to_string(),
                None => {
                    errors.push(CompileError::new(
                        format!("{fpath}.length.field"),
                        "长度表达式必须引用 `field`",
                    ));
                    return None;
                }
            };
            let scale = expr.get("scale").and_then(|v| v.as_i64()).unwrap_or(1);
            let offset = expr.get("offset").and_then(|v| v.as_i64()).unwrap_or(0);
            if scale == 0 {
                errors.push(CompileError::new(
                    format!("{fpath}.length.scale"),
                    "scale 不能为 0（请改用固定长度）",
                ));
                return None;
            }
            if scale < 0 {
                errors.push(CompileError::new(
                    format!("{fpath}.length.scale"),
                    "scale 不能为负",
                ));
                return None;
            }
            Some(LengthExpr::Field {
                name: field,
                scale,
                offset,
            })
        }
        Some(_) => {
            errors.push(CompileError::new(
                format!("{fpath}.length"),
                "length 必须是非负整数或 {field, scale?, offset?} 对象",
            ));
            None
        }
        None => {
            errors.push(CompileError::new(
                format!("{fpath}.length"),
                "该字段类型必须声明 length",
            ));
            None
        }
    }
}

fn compile_struct_field(
    fdef: &Json,
    fpath: &str,
    errors: &mut Vec<CompileError>,
) -> Option<FieldKind> {
    let struct_name = match fdef.get("struct").and_then(|v| v.as_str()) {
        Some(s) => s.to_string(),
        None => {
            errors.push(CompileError::new(
                format!("{fpath}.struct"),
                "struct 字段必须用 `struct` 指向结构名",
            ));
            return None;
        }
    };
    let length = match fdef.get("length") {
        Some(Json::Null) | None => None,
        Some(_) => Some(compile_length(fdef, fpath, errors)?),
    };
    let max_depth = fdef
        .get("max_depth")
        .and_then(|v| v.as_i64())
        .unwrap_or(DEFAULT_MAX_DEPTH as i64);
    if !(1..=4096).contains(&max_depth) {
        errors.push(CompileError::new(
            format!("{fpath}.max_depth"),
            "max_depth 必须在 1..=4096 之间",
        ));
        return None;
    }
    Some(FieldKind::Struct {
        struct_name,
        length,
        max_depth: max_depth as u32,
    })
}

fn compile_array(fdef: &Json, fpath: &str, errors: &mut Vec<CompileError>) -> Option<FieldKind> {
    let item_json = match fdef.get("item") {
        Some(item) => item,
        None => {
            errors.push(CompileError::new(
                format!("{fpath}.item"),
                "array 必须声明 `item`",
            ));
            return None;
        }
    };
    let item = compile_field(item_json, &format!("{fpath}.item"), errors)?;
    if matches!(item.kind, FieldKind::Rest) {
        errors.push(CompileError::new(
            format!("{fpath}.item"),
            "rest 字段不能作为数组元素",
        ));
        return None;
    }
    let count = match fdef.get("count") {
        Some(Json::Int(n)) if *n >= 0 => LengthExpr::Fixed(*n),
        Some(Json::Object(_)) => {
            // 复用 length 的对象语法。
            let wrapper = {
                let mut o = Json::obj();
                o.insert("length", fdef.get("count").unwrap().clone());
                o
            };
            compile_length(&wrapper, fpath, errors)?
        }
        Some(_) => {
            errors.push(CompileError::new(
                format!("{fpath}.count"),
                "count 必须是非负整数或 {field,...} 表达式",
            ));
            return None;
        }
        None => {
            errors.push(CompileError::new(
                format!("{fpath}.count"),
                "array 必须声明 `count`",
            ));
            return None;
        }
    };
    Some(FieldKind::Array {
        item: Box::new(item),
        count,
    })
}

fn compile_when(w: &Json) -> Result<When, String> {
    let field = w
        .get("field")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "when 必须引用同结构的整数字段 `field`".to_string())?
        .to_string();
    if let Some(eq) = w.get("eq").and_then(|v| v.as_i64()) {
        return Ok(When {
            field,
            op: WhenOp::Eq,
            value: eq,
        });
    }
    if let Some(ne) = w.get("ne").and_then(|v| v.as_i64()) {
        return Ok(When {
            field,
            op: WhenOp::Ne,
            value: ne,
        });
    }
    Err("when 必须包含整数 `eq` 或 `ne`".to_string())
}

fn compile_checksum(
    fdef: &Json,
    fpath: &str,
    errors: &mut Vec<CompileError>,
) -> Option<FieldKind> {
    let alg = match fdef.get("alg").and_then(|v| v.as_str()) {
        Some("sum8") => ChecksumAlg::Sum8,
        Some("xor8") => ChecksumAlg::Xor8,
        Some("sum16be") => ChecksumAlg::Sum16Be,
        Some(other) => {
            errors.push(CompileError::new(
                format!("{fpath}.alg"),
                format!("未知校验算法 `{other}`（支持 sum8/xor8/sum16be）"),
            ));
            return None;
        }
        None => {
            errors.push(CompileError::new(format!("{fpath}.alg"), "缺少校验算法"));
            return None;
        }
    };
    let from = compile_boundary(fdef.get("from"), format!("{fpath}.from"), errors)?;
    let to = compile_boundary(fdef.get("to"), format!("{fpath}.to"), errors)?;
    let skip_self = fdef.get("skip_self").and_then(|v| v.as_bool()).unwrap_or(true);
    let severity = match fdef.get("severity").and_then(|v| v.as_str()).unwrap_or("error") {
        "error" => Severity::Error,
        "warn" => Severity::Warn,
        other => {
            errors.push(CompileError::new(
                format!("{fpath}.severity"),
                format!("severity 只能是 error/warn，收到 `{other}`"),
            ));
            return None;
        }
    };
    Some(FieldKind::Checksum {
        alg,
        from,
        to,
        skip_self,
        severity,
    })
}

fn compile_boundary(
    v: Option<&Json>,
    path: String,
    errors: &mut Vec<CompileError>,
) -> Option<BoundaryRef> {
    match v.and_then(|v| v.as_str()) {
        Some("soi") => Some(BoundaryRef::Start),
        Some("eoi") => Some(BoundaryRef::End),
        Some(name) => Some(BoundaryRef::Field(name.to_string())),
        None => {
            errors.push(CompileError::new(path, "区间端点必须是 soi、eoi 或同结构字段名"));
            None
        }
    }
}

fn validate_protocol(
    _name: &str,
    root: &str,
    structs: &BTreeMap<String, StructDef>,
    errors: &mut Vec<CompileError>,
) {
    for (sname, st) in structs {
        for (i, field) in st.fields.iter().enumerate() {
            let base = format!("structs.{sname}.fields[{i}]");
            let earlier: BTreeSet<&str> =
                st.fields[..i].iter().map(|f| f.name.as_str()).collect();
            validate_field_refs(field, &base, sname, structs, &earlier, errors);
        }
    }

    // 递归结构必须在递归边上声明字节长度边界，否则可能无限展开。
    for (sname, st) in structs {
        for field in &st.fields {
            if let FieldKind::Struct {
                struct_name: target,
                length,
                ..
            } = &field.kind
            {
                if length.is_none() && reaches(target, sname, structs) {
                    errors.push(CompileError::new(
                        format!("structs.{sname}.fields.{}.length", field.name),
                        format!(
                            "字段 `{}` 指向 `{target}` 并可能递归回到 `{sname}`，必须声明 length 以限定字节边界",
                            field.name
                        ),
                    ));
                }
            }
        }
    }

    if !root.is_empty() && !structs.contains_key(root) {
        errors.push(CompileError::new("root", format!("根结构 `{root}` 不存在")));
    }
}

fn validate_field_refs(
    field: &FieldDef,
    base: &str,
    sname: &str,
    structs: &BTreeMap<String, StructDef>,
    earlier: &BTreeSet<&str>,
    errors: &mut Vec<CompileError>,
) {
    if let Some(when) = &field.when {
        if !earlier.contains(when.field.as_str()) {
            errors.push(CompileError::new(
                format!("{base}.when"),
                format!("when 引用的字段 `{}` 必须在前面声明", when.field),
            ));
        }
    }
    match &field.kind {
        FieldKind::Int { .. } | FieldKind::Rest => {}
        FieldKind::Bytes { length } | FieldKind::String_ { length } => {
            check_length_ref(length, sname, earlier, base, errors);
        }
        FieldKind::Struct {
            struct_name,
            length,
            ..
        } => {
            if !structs.contains_key(struct_name) {
                errors.push(CompileError::new(
                    format!("{base}.struct"),
                    format!("引用了未声明的结构 `{struct_name}`"),
                ));
            }
            if let Some(expr) = length {
                check_length_ref(expr, sname, earlier, base, errors);
            }
        }
        FieldKind::Array { item, count } => {
            check_length_ref(count, sname, earlier, base, errors);
            validate_field_refs(item, &format!("{base}.item"), sname, structs, earlier, errors);
        }
        FieldKind::Checksum { from, to, .. } => {
            let names: BTreeSet<&str> =
                structs[sname].fields.iter().map(|f| f.name.as_str()).collect();
            for (side, r) in [("from", from), ("to", to)] {
                if let BoundaryRef::Field(n) = r {
                    if !names.contains(n.as_str()) {
                        errors.push(CompileError::new(
                            format!("{base}.{side}"),
                            format!("校验区间端点字段 `{n}` 不在结构 `{sname}` 中"),
                        ));
                    }
                }
            }
        }
    }
}

fn check_length_ref(
    expr: &LengthExpr,
    sname: &str,
    earlier: &BTreeSet<&str>,
    base: &str,
    errors: &mut Vec<CompileError>,
) {
    if let LengthExpr::Field { name, .. } = expr {
        if !earlier.contains(name.as_str()) {
            errors.push(CompileError::new(
                base,
                format!(
                    "长度/数量引用的字段 `{name}` 必须在结构 `{sname}` 中更早出现"
                ),
            ));
        }
    }
}

/// `from` 是否能沿 struct/array 引用到达 `target`。
fn reaches(from: &str, target: &str, structs: &BTreeMap<String, StructDef>) -> bool {
    let mut stack = vec![from.to_string()];
    let mut seen = BTreeSet::new();
    while let Some(cur) = stack.pop() {
        if cur == target {
            return true;
        }
        if !seen.insert(cur.clone()) {
            continue;
        }
        if let Some(st) = structs.get(&cur) {
            for field in &st.fields {
                collect_struct_refs(&field.kind, &mut stack);
            }
        }
    }
    false
}

fn collect_struct_refs(kind: &FieldKind, out: &mut Vec<String>) {
    match kind {
        FieldKind::Struct { struct_name, .. } => out.push(struct_name.clone()),
        FieldKind::Array { item, .. } => collect_struct_refs(&item.kind, out),
        _ => {}
    }
}

impl Protocol {
    /// 对协议描述做规范化序列化：字段顺序固定，忽略空白，作为版本摘要的输入。
    pub fn canonical_json(&self) -> String {
        self.to_json().stringify()
    }

    /// 不可变版本标识：`v` + 摘要前 12 位十六进制（48 bit，冲突概率可忽略）。
    pub fn content_hash(&self) -> String {
        crate::hash::hex_encode(&crate::hash::sha256(self.canonical_json().as_bytes()))
    }

    pub fn version_id(&self) -> String {
        format!("v{}", &self.content_hash()[..12])
    }

    pub fn to_json(&self) -> Json {
        let mut root = Json::obj();
        root.insert("name", Json::from_str_value(self.name.clone()));
        if !self.description.is_empty() {
            root.insert(
                "description",
                Json::from_str_value(self.description.clone()),
            );
        }
        root.insert("root", Json::from_str_value(self.root.clone()));
        let mut structs = Json::obj();
        for (sname, st) in &self.structs {
            let mut fields = Json::Array(Vec::new());
            for f in &st.fields {
                fields.push(field_to_json(f));
            }
            let mut stj = Json::obj();
            stj.insert("fields", fields);
            structs.insert(sname.clone(), stj);
        }
        root.insert("structs", structs);
        root
    }
}

fn endian_json(e: Endian) -> Json {
    Json::from_str_value(match e {
        Endian::Big => "big",
        Endian::Little => "little",
    })
}

fn field_to_json(f: &FieldDef) -> Json {
    let mut o = Json::obj();
    o.insert("name", Json::from_str_value(f.name.clone()));
    if let Some(when) = &f.when {
        o.insert("when", when.to_json());
    }
    match &f.kind {
        FieldKind::Int {
            width,
            signed,
            endian,
            expect,
        } => {
            o.insert("type", Json::from_str_value("int"));
            o.insert("width", Json::Int(*width as i64));
            if *signed {
                o.insert("signed", Json::Bool(true));
            }
            if *width > 1 {
                o.insert("endian", endian_json(*endian));
            }
            if let Some(v) = expect {
                o.insert("expect", Json::Int(*v));
            }
        }
        FieldKind::Bytes { length } => {
            o.insert("type", Json::from_str_value("bytes"));
            o.insert("length", length.to_json());
        }
        FieldKind::String_ { length } => {
            o.insert("type", Json::from_str_value("string"));
            o.insert("length", length.to_json());
        }
        FieldKind::Struct {
            struct_name,
            length,
            max_depth,
        } => {
            o.insert("type", Json::from_str_value("struct"));
            o.insert("struct", Json::from_str_value(struct_name.clone()));
            if let Some(expr) = length {
                o.insert("length", expr.to_json());
            }
            o.insert("max_depth", Json::Int(*max_depth as i64));
        }
        FieldKind::Array { item, count } => {
            o.insert("type", Json::from_str_value("array"));
            o.insert("count", count.to_json());
            o.insert("item", field_to_json(item));
        }
        FieldKind::Rest => {
            o.insert("type", Json::from_str_value("rest"));
        }
        FieldKind::Checksum {
            alg,
            from,
            to,
            skip_self,
            severity,
        } => {
            o.insert("type", Json::from_str_value("checksum"));
            o.insert("alg", Json::from_str_value(alg.name()));
            o.insert("from", boundary_json(from));
            o.insert("to", boundary_json(to));
            o.insert("skip_self", Json::Bool(*skip_self));
            o.insert(
                "severity",
                Json::from_str_value(match severity {
                    Severity::Error => "error",
                    Severity::Warn => "warn",
                }),
            );
        }
    }
    o
}

fn boundary_json(b: &BoundaryRef) -> Json {
    match b {
        BoundaryRef::Start => Json::from_str_value("soi"),
        BoundaryRef::End => Json::from_str_value("eoi"),
        BoundaryRef::Field(name) => Json::from_str_value(name.clone()),
    }
}
