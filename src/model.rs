// 协议描述模型：从 JSON 小 DSL 加载、校验、规范化。
//
// 顶层示例：
// {
//   "name": "demo",
//   "endian": "big",
//   "max_depth": 8,
//   "max_frame": 1048576,
//   "structs": {
//     "frame": [ ...字段... ]
//   }
// }

use crate::json::Value;
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endian {
    Big,
    Little,
}

impl Endian {
    pub fn parse(s: &str) -> Option<Endian> {
        match s {
            "big" => Some(Endian::Big),
            "little" => Some(Endian::Little),
            _ => None,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Endian::Big => "big",
            Endian::Little => "little",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChecksumAlgo {
    Sum8,
    Sum16,
    Xor8,
}

impl ChecksumAlgo {
    pub fn parse(s: &str) -> Option<ChecksumAlgo> {
        match s {
            "sum8" => Some(ChecksumAlgo::Sum8),
            "sum16" => Some(ChecksumAlgo::Sum16),
            "xor8" => Some(ChecksumAlgo::Xor8),
            _ => None,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            ChecksumAlgo::Sum8 => "sum8",
            ChecksumAlgo::Sum16 => "sum16",
            ChecksumAlgo::Xor8 => "xor8",
        }
    }
    pub fn width(self) -> usize {
        match self {
            ChecksumAlgo::Sum8 | ChecksumAlgo::Xor8 => 1,
            ChecksumAlgo::Sum16 => 2,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    Ref(String),
    RefMinus(String, i64),
    Const(i64),
}

#[derive(Debug, Clone, PartialEq)]
pub struct ChecksumSpec {
    pub algo: ChecksumAlgo,
    /// 覆盖的同层字段名；None 表示默认覆盖同层全部前置字段
    pub cover: Option<Vec<String>>,
    /// 校验和计算时跳过的同层字段名（允许包含校验和自身字段名）
    pub skip: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum FieldKind {
    Int {
        bytes: usize,
        signed: bool,
        endian: Option<Endian>,
        default: Option<i64>,
        enum_map: Vec<(String, i64)>,
        checksum: Option<ChecksumSpec>,
    },
    Bytes {
        length: Option<Expr>,
        remaining: bool,
    },
    Struct(String),
    Array {
        struct_name: String,
        count: Expr,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub struct Field {
    pub name: String,
    pub kind: FieldKind,
    pub when_field: Option<String>,
    pub when_equals: i64,
}

#[derive(Debug, Clone)]
pub struct Protocol {
    pub name: String,
    pub endian: Endian,
    pub max_depth: usize,
    pub max_frame: usize,
    pub root: String,
    pub structs: HashMap<String, Vec<Field>>,
    pub order: Vec<String>,
}

impl Protocol {
    pub fn root_fields(&self) -> &[Field] {
        &self.structs[&self.root]
    }
}

pub const DEFAULT_MAX_DEPTH: usize = 8;
pub const DEFAULT_MAX_FRAME: usize = 1 << 20;

fn err(path: &str, msg: impl Into<String>) -> String {
    if path.is_empty() {
        msg.into()
    } else {
        format!("{}: {}", path, msg.into())
    }
}

fn require_obj<'a>(v: &'a Value, path: &str) -> Result<&'a Vec<(String, Value)>, String> {
    v.as_object()
        .ok_or_else(|| err(path, "必须是对象"))
}

fn get_str<'a>(o: &'a [(String, Value)], key: &str, path: &str) -> Result<&'a str, String> {
    o.iter()
        .find(|(k, _)| k == key)
        .and_then(|(_, v)| v.as_str())
        .ok_or_else(|| err(path, format!("缺少字符串字段 {:?}", key)))
}

fn opt_str<'a>(o: &'a [(String, Value)], key: &str) -> Option<&'a str> {
    o.iter().find(|(k, _)| k == key).and_then(|(_, v)| v.as_str())
}

fn check_unknown(o: &[(String, Value)], allowed: &[&str], path: &str) -> Result<(), String> {
    for (k, _) in o {
        if !allowed.contains(&k.as_str()) {
            return Err(err(path, format!("未知字段 {:?}", k)));
        }
    }
    Ok(())
}

fn parse_expr(v: &Value, path: &str) -> Result<Expr, String> {
    if let Some(i) = v.as_i128() {
        let i = i64::try_from(i).map_err(|_| err(path, "常量超出 i64 范围"))?;
        if i < 0 {
            return Err(err(path, "非负整数才允许作为常量"));
        }
        return Ok(Expr::Const(i));
    }
    if let Some(s) = v.as_str() {
        let s = s.trim();
        if let Some(rest) = s.strip_prefix('$') {
            if let Some((name, num)) = rest.split_once('-') {
                let n: i64 = num
                    .trim()
                    .parse()
                    .map_err(|_| err(path, "表达式应为 $字段 或 $字段-非负整数"))?;
                if n < 0 {
                    return Err(err(path, "减数必须非负"));
                }
                return Ok(Expr::RefMinus(name.trim().to_string(), n));
            }
            return Ok(Expr::Ref(rest.trim().to_string()));
        }
        return Err(err(path, "引用表达式必须以 $ 开头"));
    }
    Err(err(path, "长度/计数表达式必须是数字、$字段 或 $字段-常量"))
}

fn parse_checksum(v: &Value, path: &str) -> Result<ChecksumSpec, String> {
    let o = require_obj(v, path)?;
    check_unknown(o, &["algo", "cover", "skip"], path)?;
    let algo_s = get_str(o, "algo", path)?;
    let algo = ChecksumAlgo::parse(algo_s)
        .ok_or_else(|| err(path, format!("未知校验和算法 {:?}", algo_s)))?;
    let cover = match o.iter().find(|(k, _)| k == "cover") {
        Some((_, Value::Arr(a))) => {
            let mut names = Vec::new();
            for item in a {
                names.push(
                    item.as_str()
                        .ok_or_else(|| err(path, "cover 必须是字段名字符串数组"))?
                        .to_string(),
                );
            }
            Some(names)
        }
        Some(_) => return Err(err(path, "cover 必须是字符串数组")),
        None => None,
    };
    let skip = match o.iter().find(|(k, _)| k == "skip") {
        Some((_, Value::Arr(a))) => {
            let mut names = Vec::new();
            for item in a {
                names.push(
                    item.as_str()
                        .ok_or_else(|| err(path, "skip 必须是字段名字符串数组"))?
                        .to_string(),
                );
            }
            names
        }
        Some(_) => return Err(err(path, "skip 必须是字符串数组")),
        None => Vec::new(),
    };
    Ok(ChecksumSpec { algo, cover, skip })
}

fn parse_field(v: &Value, path: &str) -> Result<Field, String> {
    let o = require_obj(v, path)?;
    check_unknown(
        o,
        &[
            "name",
            "type",
            "bytes",
            "signed",
            "endian",
            "default",
            "enum",
            "checksum",
            "length",
            "remaining",
            "struct",
            "count",
            "when",
        ],
        path,
    )?;
    let name = get_str(o, "name", path)?.to_string();
    if name.is_empty() || name.contains('/') || name == "items" {
        return Err(err(path, "字段名不能为空、不能包含 '/'、不能为保留名 items"));
    }
    let ftype = get_str(o, "type", path)?;

    let when_field = match o.iter().find(|(k, _)| k == "when") {
        Some((_, Value::Obj(w))) => {
            check_unknown(w, &["field", "equals"], &format!("{}.when", path))?;
            let f = get_str(w, "field", &format!("{}.when", path))?;
            let eq = w
                .iter()
                .find(|(k, _)| k == "equals")
                .and_then(|(_, v)| v.as_i128())
                .ok_or_else(|| err(&format!("{}.when", path), "equals 必须是整数"))?;
            let eq = i64::try_from(eq)
                .map_err(|_| err(&format!("{}.when", path), "equals 超出 i64 范围"))?;
            Some((f.to_string(), eq))
        }
        Some(_) => return Err(err(path, "when 必须是 {field, equals} 对象")),
        None => None,
    };

    let kind = match ftype {
        "int" => {
            let bytes = o
                .iter()
                .find(|(k, _)| k == "bytes")
                .and_then(|(_, v)| v.as_usize())
                .ok_or_else(|| err(path, "int 字段需要 1..=8 的 bytes"))?;
            if !(1..=8).contains(&bytes) {
                return Err(err(path, "int 的 bytes 必须在 1..=8"));
            }
            let signed = o
                .iter()
                .find(|(k, _)| k == "signed")
                .map(|(_, v)| v.as_bool())
                .unwrap_or(Some(false))
                .ok_or_else(|| err(path, "signed 必须是布尔值"))?;
            let endian = match opt_str(o, "endian") {
                Some(s) => Some(
                    Endian::parse(s).ok_or_else(|| err(path, format!("未知字节序 {:?}", s)))?,
                ),
                None => None,
            };
            let default = match o.iter().find(|(k, _)| k == "default") {
                Some((_, v)) => Some(
                    i64::try_from(v.as_i128().ok_or_else(|| err(path, "default 必须是整数"))?)
                        .map_err(|_| err(path, "default 超出 i64 范围"))?,
                ),
                None => None,
            };
            let enum_map = match o.iter().find(|(k, _)| k == "enum") {
                Some((_, Value::Obj(entries))) => {
                    let mut map = Vec::new();
                    for (label, val) in entries {
                        let n = val
                            .as_i128()
                            .ok_or_else(|| err(path, "enum 值必须是整数"))?;
                        let n = i64::try_from(n)
                            .map_err(|_| err(path, "enum 值超出 i64 范围"))?;
                        map.push((label.clone(), n));
                    }
                    map
                }
                Some(_) => return Err(err(path, "enum 必须是对象")),
                None => Vec::new(),
            };
            let checksum = match o.iter().find(|(k, _)| k == "checksum") {
                Some((_, v)) => Some(parse_checksum(v, &format!("{}.checksum", path))?),
                None => None,
            };
            if let Some(cs) = &checksum {
                if cs.algo.width() != bytes {
                    return Err(err(
                        path,
                        format!(
                            "校验和算法 {} 需要 {} 字节宽度，但字段 bytes={}",
                            cs.algo.as_str(),
                            cs.algo.width(),
                            bytes
                        ),
                    ));
                }
            }
            FieldKind::Int {
                bytes,
                signed,
                endian,
                default,
                enum_map,
                checksum,
            }
        }
        "bytes" => {
            check_unknown(
                o,
                &["name", "type", "length", "remaining", "when"],
                path,
            )?;
            let remaining = o
                .iter()
                .find(|(k, _)| k == "remaining")
                .map(|(_, v)| v.as_bool())
                .unwrap_or(Some(false))
                .ok_or_else(|| err(path, "remaining 必须是布尔值"))?;
            let length = match o.iter().find(|(k, _)| k == "length") {
                Some((_, v)) => Some(parse_expr(v, path)?),
                None => None,
            };
            if remaining && length.is_some() {
                return Err(err(path, "bytes 不能同时声明 remaining 和 length"));
            }
            if !remaining && length.is_none() {
                return Err(err(path, "bytes 必须声明 length 或 remaining:true"));
            }
            FieldKind::Bytes { length, remaining }
        }
        "struct" => {
            check_unknown(o, &["name", "type", "struct", "when"], path)?;
            let struct_name = get_str(o, "struct", path)?.to_string();
            FieldKind::Struct(struct_name)
        }
        "array" => {
            check_unknown(o, &["name", "type", "struct", "count", "when"], path)?;
            let struct_name = get_str(o, "struct", path)?.to_string();
            let count_v = o
                .iter()
                .find(|(k, _)| k == "count")
                .map(|(_, v)| v)
                .ok_or_else(|| err(path, "array 需要 count 表达式"))?;
            let count = parse_expr(count_v, path)?;
            FieldKind::Array { struct_name, count }
        }
        other => return Err(err(path, format!("未知字段类型 {:?}", other))),
    };

    Ok(Field {
        name,
        kind,
        when_field: when_field.as_ref().map(|(f, _)| f.clone()),
        when_equals: when_field.as_ref().map(|(_, e)| *e).unwrap_or(0),
    })
}

pub fn load_protocol(v: &Value) -> Result<Protocol, String> {
    let root_o = require_obj(v, "协议描述")?;
    check_unknown(
        root_o,
        &["name", "endian", "max_depth", "max_frame", "root", "structs"],
        "协议描述",
    )?;
    let name = get_str(root_o, "name", "协议描述")?.to_string();
    let endian = match opt_str(root_o, "endian") {
        None => Endian::Big,
        Some(s) => Endian::parse(s)
            .ok_or_else(|| format!("协议描述: 未知字节序 {:?}（仅 big/little）", s))?,
    };
    let max_depth = match root_o.iter().find(|(k, _)| k == "max_depth") {
        Some((_, v)) => {
            let n = v
                .as_usize()
                .ok_or_else(|| "协议描述: max_depth 必须是非负整数".to_string())?;
            if !(1..=64).contains(&n) {
                return Err("协议描述: max_depth 必须在 1..=64".to_string());
            }
            n
        }
        None => DEFAULT_MAX_DEPTH,
    };
    let max_frame = match root_o.iter().find(|(k, _)| k == "max_frame") {
        Some((_, v)) => {
            let n = v
                .as_usize()
                .ok_or_else(|| "协议描述: max_frame 必须是非负整数".to_string())?;
            if !(16..=(1 << 28)).contains(&n) {
                return Err("协议描述: max_frame 必须在 16..=268435456".to_string());
            }
            n
        }
        None => DEFAULT_MAX_FRAME,
    };
    let root = opt_str(root_o, "root").unwrap_or("frame").to_string();

    let structs_v = root_o
        .iter()
        .find(|(k, _)| k == "structs")
        .map(|(_, v)| v)
        .ok_or_else(|| "协议描述: 缺少 structs 对象".to_string())?;
    let structs_o = require_obj(structs_v, "structs")?;
    if structs_o.is_empty() {
        return Err("structs: 至少要声明一个结构".to_string());
    }

    let mut structs = HashMap::new();
    let mut order = Vec::new();
    for (sname, fields_v) in structs_o {
        let arr = fields_v
            .as_array()
            .ok_or_else(|| format!("structs.{}: 字段列表必须是数组", sname))?;
        if arr.is_empty() {
            return Err(format!("structs.{}: 结构不能为空", sname));
        }
        let mut fields = Vec::new();
        for (idx, fv) in arr.iter().enumerate() {
            let f = parse_field(fv, &format!("structs.{}.[{}]", sname, idx))?;
            fields.push(f);
        }
        // 字段名唯一
        let mut seen = std::collections::HashSet::new();
        for f in &fields {
            if !seen.insert(&f.name) {
                return Err(format!("structs.{}: 字段名 {:?} 重复", sname, f.name));
            }
        }
        order.push(sname.clone());
        structs.insert(sname.clone(), fields);
    }

    if !structs.contains_key(&root) {
        return Err(format!("协议描述: root {:?} 未在 structs 中声明", root));
    }

    let proto = Protocol {
        name,
        endian,
        max_depth,
        max_frame,
        root,
        structs,
        order,
    };
    validate_references(&proto)?;
    Ok(proto)
}

fn validate_references(proto: &Protocol) -> Result<(), String> {
    for sname in &proto.order {
        let fields = &proto.structs[sname];
        let earlier = |idx: usize, target: &str| -> bool {
            fields[..idx].iter().any(|f| f.name == target)
        };
        for (idx, f) in fields.iter().enumerate() {
            match &f.kind {
                FieldKind::Int {
                    bytes,
                    signed,
                    default,
                    enum_map,
                    checksum,
                    ..
                } => {
                    let max = if *signed {
                        (1i128 << (bytes * 8 - 1)) - 1
                    } else {
                        (1i128 << (bytes * 8)) - 1
                    };
                    let min = if *signed {
                -(1i128 << (bytes * 8 - 1))
                    } else {
                        0
                    };
                    let check_val = |n: i64| -> Result<(), String> {
                        let n = n as i128;
                        if n < min || n > max {
                            return Err(format!(
                                "structs.{}.{}: 值 {} 超出 {} 字节{}整数范围 [{}, {}]",
                                sname, f.name, n, bytes,
                                if *signed { "有" } else { "无" },
                                min, max
                            ));
                        }
                        Ok(())
                    };
                    if let Some(d) = default {
                        check_val(*d)?;
                    }
                    let mut evals = std::collections::HashSet::new();
                    for (label, n) in enum_map {
                        check_val(*n)?;
                        if !evals.insert(*n) {
                            return Err(format!(
                                "structs.{}.{}: enum 值 {} 重复（标签 {:?}）",
                                sname, f.name, n, label
                            ));
                        }
                    }
                    if let Some(cs) = checksum {
                        if let Some(cover) = &cs.cover {
                            for name in cover {
                                if name == &f.name {
                                    return Err(format!(
                                        "structs.{}.{}: cover 不能包含校验和自身；如需跳过请使用 skip",
                                        sname, f.name
                                    ));
                                }
                                if !earlier(idx, name) {
                                    return Err(format!(
                                        "structs.{}.{}: cover 引用的 {:?} 必须是更早声明的同层字段",
                                        sname, f.name, name
                                    ));
                                }
                            }
                        }
                        for name in &cs.skip {
                            if !fields.iter().any(|x| &x.name == name) {
                                return Err(format!(
                                    "structs.{}.{}: skip 引用了不存在的同层字段 {:?}",
                                    sname, f.name, name
                                ));
                            }
                        }
                    }
                }
                FieldKind::Bytes { length, remaining } => {
                    if *remaining && idx != fields.len() - 1 {
                        return Err(format!(
                            "structs.{}.{}: remaining 字段必须是结构的最后一个字段",
                            sname, f.name
                        ));
                    }
                    if let Some(e) = length {
                        check_expr_refs(e, proto, sname, fields, idx, &f.name)?;
                    }
                }
                FieldKind::Struct(target) => {
                    if !proto.structs.contains_key(target) {
                        return Err(format!(
                            "structs.{}.{}: 引用了未声明的结构 {:?}",
                            sname, f.name, target
                        ));
                    }
                }
                FieldKind::Array { struct_name, count } => {
                    if !proto.structs.contains_key(struct_name) {
                        return Err(format!(
                            "structs.{}.{}: 元素结构 {:?} 未声明",
                            sname, f.name, struct_name
                        ));
                    }
                    if idx != fields.len() - 1 {
                        return Err(format!(
                            "structs.{}.{}: array 字段必须是结构的最后一个字段",
                            sname, f.name
                        ));
                    }
                    check_expr_refs(count, proto, sname, fields, idx, &f.name)?;
                }
            }
            if let Some(wf) = &f.when_field {
                if !earlier(idx, wf) {
                    return Err(format!(
                        "structs.{}.{}: when 引用的 {:?} 必须是更早声明的同层 int 字段",
                        sname, f.name, wf
                    ));
                }
                match &fields[..idx].iter().find(|x| &x.name == wf).unwrap().kind {
                    FieldKind::Int { .. } => {}
                    _ => {
                        return Err(format!(
                            "structs.{}.{}: when 只能依赖 int 字段 {:?}",
                            sname, f.name, wf
                        ))
                    }
                }
            }
        }
    }
    Ok(())
}

fn check_expr_refs(
    e: &Expr,
    _proto: &Protocol,
    sname: &str,
    fields: &[Field],
    idx: usize,
    fname: &str,
) -> Result<(), String> {
    let target = match e {
        Expr::Ref(n) | Expr::RefMinus(n, _) => n,
        Expr::Const(_) => return Ok(()),
    };
    let dep = fields[..idx]
        .iter()
        .find(|f| &f.name == target)
        .ok_or_else(|| {
            format!(
                "structs.{}.{}: 表达式引用的 {:?} 必须是更早声明的同层字段",
                sname, fname, target
            )
        })?;
    match dep.kind {
        FieldKind::Int { .. } => Ok(()),
        _ => Err(format!(
            "structs.{}.{}: 表达式只能依赖 int 字段 {:?}",
            sname, fname, target
        )),
    }
}

pub fn protocol_to_json(p: &Protocol) -> Value {
    let mut structs = Vec::new();
    for sname in &p.order {
        let fields: Vec<Value> = p.structs[sname].iter().map(field_to_json).collect();
        structs.push((sname.clone(), Value::Arr(fields)));
    }
    Value::Obj(vec![
        ("name".to_string(), Value::Str(p.name.clone())),
        ("endian".to_string(), Value::Str(p.endian.as_str().to_string())),
        ("max_depth".to_string(), Value::Int(p.max_depth as i128)),
        ("max_frame".to_string(), Value::Int(p.max_frame as i128)),
        ("root".to_string(), Value::Str(p.root.clone())),
        ("structs".to_string(), Value::Obj(structs)),
    ])
}

fn expr_to_json(e: &Expr) -> Value {
    match e {
        Expr::Ref(n) => Value::Str(format!("${}", n)),
        Expr::RefMinus(n, k) => Value::Str(format!("${}-{}", n, k)),
        Expr::Const(c) => Value::Int(*c as i128),
    }
}

fn field_to_json(f: &Field) -> Value {
    let mut o = vec![("name".to_string(), Value::Str(f.name.clone()))];
    match &f.kind {
        FieldKind::Int {
            bytes,
            signed,
            endian,
            default,
            enum_map,
            checksum,
        } => {
            o.push(("type".to_string(), Value::Str("int".to_string())));
            o.push(("bytes".to_string(), Value::Int(*bytes as i128)));
            if *signed {
                o.push(("signed".to_string(), Value::Bool(true)));
            }
            if let Some(e) = endian {
                o.push(("endian".to_string(), Value::Str(e.as_str().to_string())));
            }
            if let Some(d) = default {
                o.push(("default".to_string(), Value::Int(*d as i128)));
            }
            if !enum_map.is_empty() {
                o.push((
                    "enum".to_string(),
                    Value::Obj(
                        enum_map
                            .iter()
                            .map(|(k, v)| (k.clone(), Value::Int(*v as i128)))
                            .collect(),
                    ),
                ));
            }
            if let Some(cs) = checksum {
                let mut c = vec![(
                    "algo".to_string(),
                    Value::Str(cs.algo.as_str().to_string()),
                )];
                if let Some(cover) = &cs.cover {
                    c.push((
                        "cover".to_string(),
                        Value::Arr(cover.iter().map(|s| Value::Str(s.clone())).collect()),
                    ));
                }
                if !cs.skip.is_empty() {
                    c.push((
                        "skip".to_string(),
                        Value::Arr(cs.skip.iter().map(|s| Value::Str(s.clone())).collect()),
                    ));
                }
                o.push(("checksum".to_string(), Value::Obj(c)));
            }
        }
        FieldKind::Bytes { length, remaining } => {
            o.push(("type".to_string(), Value::Str("bytes".to_string())));
            if *remaining {
                o.push(("remaining".to_string(), Value::Bool(true)));
            } else if let Some(e) = length {
                o.push(("length".to_string(), expr_to_json(e)));
            }
        }
        FieldKind::Struct(name) => {
            o.push(("type".to_string(), Value::Str("struct".to_string())));
            o.push(("struct".to_string(), Value::Str(name.clone())));
        }
        FieldKind::Array { struct_name, count } => {
            o.push(("type".to_string(), Value::Str("array".to_string())));
            o.push(("struct".to_string(), Value::Str(struct_name.clone())));
            o.push(("count".to_string(), expr_to_json(count)));
        }
    }
    if let Some(wf) = &f.when_field {
        o.push((
            "when".to_string(),
            Value::Obj(vec![
                ("field".to_string(), Value::Str(wf.clone())),
                ("equals".to_string(), Value::Int(f.when_equals as i128)),
            ]),
        ));
    }
    Value::Obj(o)
}
