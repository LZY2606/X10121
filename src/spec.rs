use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProtocolSpec {
    pub name: String,
    #[serde(default)]
    pub config: SpecConfig,
    #[serde(default)]
    pub defs: Vec<StructDef>,
    pub root: Field,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct SpecConfig {
    /// 递归 ref 的最大展开深度
    pub max_depth: usize,
    /// 单次解析允许的最大字段数（防御恶意输入）
    pub max_fields: usize,
    /// length_of 解析出的单字段长度上限
    pub max_len: usize,
}

impl Default for SpecConfig {
    fn default() -> Self {
        SpecConfig {
            max_depth: 16,
            max_fields: 100_000,
            max_len: 1 << 20,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StructDef {
    pub name: String,
    pub fields: Vec<Field>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Endian {
    Big,
    Little,
}

impl Default for Endian {
    fn default() -> Self {
        Endian::Big
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Cond {
    pub field: String,
    #[serde(default)]
    pub equals: Option<u64>,
    #[serde(default)]
    pub not_equals: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Field {
    Uint(UintField),
    Bytes(BytesField),
    Struct(StructField),
    Ref(RefField),
    Checksum(ChecksumField),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UintField {
    pub name: String,
    /// 1 / 2 / 4 / 8 字节定长整数
    pub size: usize,
    #[serde(default)]
    pub endian: Endian,
    #[serde(default, rename = "if")]
    pub cond: Option<Cond>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BytesField {
    pub name: String,
    #[serde(default)]
    pub length: Option<usize>,
    /// 引用之前某个整数字段的值作为长度
    #[serde(default)]
    pub length_of: Option<String>,
    #[serde(default, rename = "if")]
    pub cond: Option<Cond>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StructField {
    pub name: String,
    pub fields: Vec<Field>,
    /// 可选：声明该子结构的总字节跨度，子字段不得越界
    #[serde(default)]
    pub length: Option<usize>,
    #[serde(default)]
    pub length_of: Option<String>,
    #[serde(default, rename = "if")]
    pub cond: Option<Cond>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RefField {
    pub name: String,
    /// 引用 defs 中的命名结构（可形成递归）
    #[serde(rename = "def")]
    pub def_name: String,
    #[serde(default, rename = "if")]
    pub cond: Option<Cond>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChecksumAlgo {
    Sum8,
    Xor8,
    Sum16,
}

impl ChecksumAlgo {
    pub fn size(self) -> usize {
        match self {
            ChecksumAlgo::Sum8 | ChecksumAlgo::Xor8 => 1,
            ChecksumAlgo::Sum16 => 2,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChecksumRange {
    /// 起始字段名（同一结构内、先于校验和字段声明）
    pub from: String,
    /// 结束字段名（可以是校验和字段自身，配合 skip_self 排除自身字节）
    pub to: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChecksumField {
    pub name: String,
    pub algo: ChecksumAlgo,
    pub range: ChecksumRange,
    /// 覆盖区间包含自身时跳过自身字节，默认 true
    #[serde(default = "default_true")]
    pub skip_self: bool,
    #[serde(default, rename = "if")]
    pub cond: Option<Cond>,
}

fn default_true() -> bool {
    true
}

impl Field {
    pub fn name(&self) -> &str {
        match self {
            Field::Uint(f) => &f.name,
            Field::Bytes(f) => &f.name,
            Field::Struct(f) => &f.name,
            Field::Ref(f) => &f.name,
            Field::Checksum(f) => &f.name,
        }
    }

    pub fn cond(&self) -> Option<&Cond> {
        match self {
            Field::Uint(f) => f.cond.as_ref(),
            Field::Bytes(f) => f.cond.as_ref(),
            Field::Struct(f) => f.cond.as_ref(),
            Field::Ref(f) => f.cond.as_ref(),
            Field::Checksum(f) => f.cond.as_ref(),
        }
    }
}

/// 静态校验协议描述。返回 Err(中文描述) 表示描述非法。
pub fn validate(spec: &ProtocolSpec) -> Result<(), String> {
    if spec.name.trim().is_empty() {
        return Err("协议名称不能为空".to_string());
    }
    if spec.config.max_depth == 0 {
        return Err("config.max_depth 必须 ≥ 1".to_string());
    }
    if spec.config.max_fields == 0 {
        return Err("config.max_fields 必须 ≥ 1".to_string());
    }
    let mut defs: HashMap<&str, &StructDef> = HashMap::new();
    for d in &spec.defs {
        if defs.insert(d.name.as_str(), d).is_some() {
            return Err(format!("重复的 def 名称: {}", d.name));
        }
    }
    match &spec.root {
        Field::Struct(_) | Field::Ref(_) => {}
        other => {
            return Err(format!(
                "root 必须是 struct 或 ref，当前是 {}",
                other.name()
            ))
        }
    }
    let empty = HashSet::new();
    validate_field(&spec.root, &empty, false, &defs)?;
    for d in &spec.defs {
        // def 可能被任意上下文引用，外部引用允许在运行时解析
        validate_fields(&d.fields, &empty, true, &defs)?;
    }
    check_recursion_guard(spec, &defs)?;
    Ok(())
}

fn check_ref(
    name: &str,
    local_uints: &HashSet<String>,
    ancestors: &HashSet<String>,
    allow_external: bool,
    what: &str,
) -> Result<(), String> {
    if local_uints.contains(name) || ancestors.contains(name) || allow_external {
        Ok(())
    } else {
        Err(format!(
            "{}引用了未知的前置整数字段: {}",
            what, name
        ))
    }
}

fn validate_field(
    field: &Field,
    ancestors: &HashSet<String>,
    allow_external: bool,
    defs: &HashMap<&str, &StructDef>,
) -> Result<(), String> {
    match field {
        Field::Struct(s) => validate_fields(&s.fields, ancestors, allow_external, defs),
        Field::Ref(r) => {
            if !defs.contains_key(r.def_name.as_str()) {
                return Err(format!("ref 引用了未定义的 def: {}", r.def_name));
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn validate_fields(
    fields: &[Field],
    ancestors: &HashSet<String>,
    allow_external: bool,
    defs: &HashMap<&str, &StructDef>,
) -> Result<(), String> {
    let mut local_uints: HashSet<String> = HashSet::new();
    let mut local_names: HashSet<String> = HashSet::new();
    for f in fields {
        let name = f.name().to_string();
        if name.is_empty() {
            return Err("字段名不能为空".to_string());
        }
        if !local_names.insert(name.clone()) {
            return Err(format!("同一结构内字段重名: {}", name));
        }
        if let Some(c) = f.cond() {
            check_ref(&c.field, &local_uints, ancestors, allow_external, "条件 ")?;
            if c.equals.is_none() && c.not_equals.is_none() {
                return Err(format!("字段 {} 的条件缺少 equals / not_equals", name));
            }
        }
        match f {
            Field::Uint(u) => {
                if ![1, 2, 4, 8].contains(&u.size) {
                    return Err(format!("uint 字段 {} 的 size 必须是 1/2/4/8", name));
                }
                local_uints.insert(name);
            }
            Field::Bytes(b) => {
                match (&b.length, &b.length_of) {
                    (Some(_), Some(_)) => {
                        return Err(format!("bytes 字段 {} 同时给了 length 和 length_of", name))
                    }
                    (None, None) => {
                        return Err(format!("bytes 字段 {} 需要 length 或 length_of", name))
                    }
                    _ => {}
                }
                if let Some(lo) = &b.length_of {
                    check_ref(lo, &local_uints, ancestors, allow_external, "length_of ")?;
                }
            }
            Field::Struct(s) => {
                if s.length.is_some() && s.length_of.is_some() {
                    return Err(format!("struct 字段 {} 同时给了 length 和 length_of", name));
                }
                if let Some(lo) = &s.length_of {
                    check_ref(lo, &local_uints, ancestors, allow_external, "length_of ")?;
                }
                let mut child_ancestors = ancestors.clone();
                child_ancestors.extend(local_uints.iter().cloned());
                validate_fields(&s.fields, &child_ancestors, allow_external, defs)?;
            }
            Field::Ref(r) => {
                if !defs.contains_key(r.def_name.as_str()) {
                    return Err(format!("ref 字段 {} 引用了未定义的 def: {}", name, r.def_name));
                }
            }
            Field::Checksum(c) => {
                if c.range.from == c.name || !local_names.contains(&c.range.from) {
                    return Err(format!(
                        "校验和 {} 的区间起点 {} 不是先于它声明的字段",
                        name, c.range.from
                    ));
                }
                if c.range.to != c.name && !local_names.contains(&c.range.to) {
                    return Err(format!(
                        "校验和 {} 的区间终点 {} 不是先于它声明的字段（也不是自身）",
                        name, c.range.to
                    ));
                }
                local_uints.insert(name);
            }
        }
    }
    Ok(())
}

/// 递归守卫：def 引用图中不允许存在“全程无条件”的环，否则递归永不终止。
fn check_recursion_guard(
    spec: &ProtocolSpec,
    defs: &HashMap<&str, &StructDef>,
) -> Result<(), String> {
    // 收集每个 def 的无条件出边
    let mut unguarded: HashMap<String, Vec<String>> = HashMap::new();
    for d in &spec.defs {
        let mut edges = Vec::new();
        collect_unguarded_refs(&d.fields, false, &mut edges);
        unguarded.insert(d.name.clone(), edges);
    }
    // 从每个 def 出发，沿无条件边能否回到自身
    for d in &spec.defs {
        let mut stack: Vec<&str> = unguarded
            .get(&d.name)
            .map(|v| v.iter().map(|s| s.as_str()).collect())
            .unwrap_or_default();
        let mut visited: HashSet<&str> = HashSet::new();
        while let Some(cur) = stack.pop() {
            if cur == d.name {
                return Err(format!(
                    "def {} 存在无条件的递归引用，解析永远不会终止；请为递归 ref 加上 if 条件",
                    d.name
                ));
            }
            if visited.insert(cur) {
                if let Some(next) = unguarded.get(cur) {
                    stack.extend(next.iter().map(|s| s.as_str()));
                }
            }
        }
    }
    Ok(())
}

fn collect_unguarded_refs(fields: &[Field], guarded: bool, out: &mut Vec<String>) {
    for f in fields {
        let here_guarded = guarded || f.cond().is_some();
        match f {
            Field::Ref(r) => {
                if !here_guarded {
                    out.push(r.def_name.clone());
                }
            }
            Field::Struct(s) => collect_unguarded_refs(&s.fields, here_guarded, out),
            _ => {}
        }
    }
}
