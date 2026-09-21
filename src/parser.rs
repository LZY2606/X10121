use crate::error::LabResult;
use crate::protocol::{
    json_as_u64, ChecksumAlgo, CondOp, Endian, Field, LengthOf, Protocol, Severity, When,
};
use serde::Serialize;
use serde_json::{json, Value};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Complete,
    Incomplete,
    Error,
}

#[derive(Debug, Clone, Serialize)]
pub struct Node {
    pub kind: String,
    pub name: String,
    pub start: usize,
    pub end: usize,
    pub value: Value,
    #[serde(default)]
    pub children: Vec<Node>,
    #[serde(default = "default_true", rename = "present")]
    pub present: bool,
}

#[allow(dead_code)]
fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
pub struct Diagnostic {
    pub severity: String,
    pub code: String,
    pub message: String,
    pub path: Vec<String>,
    pub offset: usize,
    /// 仅 incomplete：仍需字节数的下界。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub need_more: Option<usize>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Outcome {
    pub status: Status,
    pub root: Node,
    pub diagnostics: Vec<Diagnostic>,
    pub consumed: usize,
}

#[derive(Debug, Clone)]
struct Stop {
    severity: Severity,
    code: String,
    message: String,
    path: Vec<String>,
    offset: usize,
    need_more: Option<usize>,
}

struct Frame {
    node: Node,
    /// 已落盘的兄弟字段节点（按出现顺序）。
    placed: Vec<Node>,
    pos: usize,
    /// 本结构作用域内待验证的校验和。
    pending: Vec<PendingChecksum>,
}

struct PendingChecksum {
    node_start: usize,
    width: usize,
    algo: ChecksumAlgo,
    covers: Vec<String>,
    skip_self: bool,
    mismatch: Severity,
}

/// 解析入口：输入不足返回 Incomplete，违反协议返回 Error。
pub fn parse(protocol: &Protocol, data: &[u8]) -> LabResult<Outcome> {
    protocol.validate()?;
    let mut frame = Frame {
        node: Node {
            kind: "struct".to_string(),
            name: protocol.root.clone(),
            start: 0,
            end: 0,
            value: json!({}),
            children: Vec::new(),
            present: true,
        },
        placed: Vec::new(),
        pos: 0,
        pending: Vec::new(),
    };
    let mut diagnostics: Vec<Diagnostic> = Vec::new();

    let stop = match parse_struct(
        protocol,
        &protocol.root.clone(),
        data,
        0,
        None,
        false,
        0,
        vec![protocol.root.clone()],
        &mut frame,
        &mut diagnostics,
    ) {
        Ok(()) => {
            // 根结构剩余字节保留为 remainder，不视为协议错误。
            if frame.pos < data.len() {
                let rem = Node {
                    kind: "remainder".to_string(),
                    name: "remainder".to_string(),
                    start: frame.pos,
                    end: data.len(),
                    value: json!({ "hex": crate::hex::encode(&data[frame.pos..]) }),
                    children: Vec::new(),
                    present: true,
                };
                frame.placed.push(rem);
                frame.pos = data.len();
            }
            None
        }
        Err(stop) => Some(stop),
    };

    // 根结构解析完整后核对其作用域校验和（子结构已各自完成核对）。
    let root_pending = std::mem::take(&mut frame.pending);
    for pc in root_pending {
        verify_checksum(data, &mut frame.placed, &pc, &mut diagnostics);
    }

    frame.node.children = frame.placed;
    frame.node.end = frame.pos;

    let has_error = diagnostics.iter().any(|d| d.severity == "error");
    let status = if let Some(s) = &stop {
        match s.severity {
            Severity::Error => Status::Error,
            Severity::Warning => {
                if has_error {
                    Status::Error
                } else {
                    Status::Incomplete
                }
            }
        }
    } else if has_error {
        Status::Error
    } else {
        Status::Complete
    };

    if let Some(s) = stop {
        diagnostics.push(Diagnostic {
            severity: match s.severity {
                Severity::Error => "error",
                Severity::Warning => "incomplete",
            }
            .to_string(),
            code: s.code,
            message: s.message,
            path: s.path,
            offset: s.offset,
            need_more: s.need_more,
        });
    }

    Ok(Outcome {
        status,
        root: frame.node,
        diagnostics,
        consumed: frame.pos,
    })
}

#[allow(clippy::too_many_arguments)]
fn parse_struct(
    protocol: &Protocol,
    sname: &str,
    data: &[u8],
    start: usize,
    hard_end: Option<usize>,
    bounded: bool,
    depth: usize,
    path: Vec<String>,
    frame: &mut Frame,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<(), Stop> {
    let fields = protocol
        .structs
        .get(sname)
        .ok_or_else(|| fatal("unknown_struct", format!("结构 '{sname}' 不存在"), &path, start))?
        .clone();

    for field in &fields {
        if !conditions_hold(field.when(), frame, &path)? {
            let absent = Node {
                kind: field_kind(field).to_string(),
                name: field.name().to_string(),
                start: frame.pos,
                end: frame.pos,
                value: json!({ "present": false }),
                children: Vec::new(),
                present: false,
            };
            frame.placed.push(absent);
            continue;
        }
        parse_field(
            protocol,
            field,
            data,
            hard_end,
            bounded,
            depth,
            path.clone(),
            frame,
            diagnostics,
        )?;
    }

    // 本结构作用域的校验和在其全部兄弟字段落位后验证。
    let pending = std::mem::take(&mut frame.pending);
    for pc in pending {
        verify_checksum(data, &mut frame.placed, &pc, diagnostics);
    }

    if bounded {
        if let Some(end) = hard_end {
            if frame.pos != end {
                // 有界结构内部仍有剩余：最深结构产生 trailing 诊断（警告）。
                diagnostics.push(Diagnostic {
                    severity: "warning".to_string(),
                    code: "trailing_bytes".to_string(),
                    message: format!(
                        "结构 '{sname}' 在有界区间内剩余 {} 个未声明字节",
                        end.saturating_sub(frame.pos)
                    ),
                    path: path.clone(),
                    offset: frame.pos,
                    need_more: None,
                });
                frame.pos = end;
            }
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn parse_field(
    protocol: &Protocol,
    field: &Field,
    data: &[u8],
    hard_end: Option<usize>,
    bounded: bool,
    depth: usize,
    path: Vec<String>,
    frame: &mut Frame,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<(), Stop> {
    let fpath = {
        let mut p = path.clone();
        p.push(field.name().to_string());
        p
    };
    match field {
        Field::Int {
            name,
            width,
            endian,
            expect,
            ..
        } => {
            require(data, frame.pos, *width, hard_end, &fpath, name)?;
            let raw = &data[frame.pos..frame.pos + width];
            let value = endian.read_u64(raw);
            if let Some(exp) = expect {
                if let Some(want) = json_as_u64(exp) {
                    if want != value {
                        return Err(Stop {
                            severity: Severity::Error,
                            code: "unexpected_value".to_string(),
                            message: format!(
                                "字段 '{name}' 的值为 0x{value:x}，期望 0x{want:x}"
                            ),
                            path: fpath,
                            offset: frame.pos,
                            need_more: None,
                        });
                    }
                }
            }
            let node = Node {
                kind: "int".to_string(),
                name: name.clone(),
                start: frame.pos,
                end: frame.pos + width,
                value: json!({ "int": value, "hex": crate::hex::encode(raw) }),
                children: Vec::new(),
                present: true,
            };
            frame.pos += width;
            frame.placed.push(node);
            Ok(())
        }
        Field::Bytes { name, len, .. } => {
            let (length, _len_source) = resolve_length(len, frame, &fpath, frame.pos)?;
            let start = frame.pos;
            require(data, start, length, hard_end, &fpath, name)?;
            let raw = &data[start..start + length];
            frame.pos = start + length;
            frame.placed.push(Node {
                kind: "bytes".to_string(),
                name: name.clone(),
                start,
                end: start + length,
                value: json!({ "hex": crate::hex::encode(raw), "length": length }),
                children: Vec::new(),
                present: true,
            });
            Ok(())
        }
        Field::Payload {
            name,
            len,
            struct_ref,
        } => {
            let (length, _) = resolve_length(len, frame, &fpath, frame.pos)?;
            let start = frame.pos;
            require(data, start, length, hard_end, &fpath, name)?;
            let mut node = Node {
                kind: "payload".to_string(),
                name: name.clone(),
                start,
                end: start + length,
                value: json!({ "length": length, "hex": crate::hex::encode(&data[start..start + length]) }),
                children: Vec::new(),
                present: true,
            };
            if let Some(r) = struct_ref {
                let next_depth = depth + 1;
                if next_depth > protocol.max_depth {
                    return Err(Stop {
                        severity: Severity::Error,
                        code: "depth_exceeded".to_string(),
                        message: format!(
                            "递归深度 {next_depth} 超过上限 {}",
                            protocol.max_depth
                        ),
                        path: fpath,
                        offset: start,
                        need_more: None,
                    });
                }
                let mut child_frame = Frame {
                    node: Node {
                        kind: "struct".to_string(),
                        name: r.clone(),
                        start,
                        end: start + length,
                        value: json!({}),
                        children: Vec::new(),
                        present: true,
                    },
                    placed: Vec::new(),
                    pos: start,
                    pending: Vec::new(),
                };
                let mut child_path = path.clone();
                child_path.push(name.clone());
                child_path.push(r.clone());
                let mut child_diag: Vec<Diagnostic> = Vec::new();
                let inner = parse_struct(
                    protocol,
                    r,
                    data,
                    start,
                    Some(start + length),
                    true,
                    next_depth,
                    child_path,
                    &mut child_frame,
                    &mut child_diag,
                );
                child_frame.node.children = child_frame.placed;
                child_frame.node.end = start + length;
                node.children.push(child_frame.node);
                diagnostics.extend(child_diag);
                inner?;
            }
            frame.pos = start + length;
            frame.placed.push(node);
            Ok(())
        }
        Field::Struct {
            name,
            struct_ref,
            ..
        }
        | Field::Ref {
            name,
            struct_ref,
            ..
        } => {
            let is_ref = matches!(field, Field::Ref { .. });
            let next_depth = if is_ref { depth + 1 } else { depth };
            if is_ref && next_depth > protocol.max_depth {
                return Err(Stop {
                    severity: Severity::Error,
                    code: "depth_exceeded".to_string(),
                    message: format!(
                        "递归深度 {next_depth} 超过上限 {}",
                        protocol.max_depth
                    ),
                    path: fpath,
                    offset: frame.pos,
                    need_more: None,
                });
            }
            let mut sub = Frame {
                node: Node {
                    kind: "struct".to_string(),
                    name: struct_ref.clone(),
                    start: frame.pos,
                    end: frame.pos,
                    value: json!({}),
                    children: Vec::new(),
                    present: true,
                },
                placed: Vec::new(),
                pos: frame.pos,
                pending: Vec::new(),
            };
            let mut sub_path = path.clone();
            sub_path.push(name.clone());
            sub_path.push(struct_ref.clone());
            let mut sub_diag: Vec<Diagnostic> = Vec::new();
            let inner = parse_struct(
                protocol,
                struct_ref,
                data,
                frame.pos,
                hard_end,
                bounded,
                next_depth,
                sub_path,
                &mut sub,
                &mut sub_diag,
            );
            diagnostics.extend(sub_diag);
            inner?;
            sub.node.children = sub.placed;
            sub.node.end = sub.pos;
            let end = sub.pos;
            frame.pos = end;
            frame.placed.push(Node {
                kind: if is_ref { "ref" } else { "struct" }.to_string(),
                name: name.clone(),
                start: sub.node.start,
                end,
                value: json!({}),
                children: vec![sub.node],
                present: true,
            });
            Ok(())
        }
        Field::Checksum {
            name,
            width,
            algo,
            covers,
            skip_self,
            mismatch,
            ..
        } => {
            require(data, frame.pos, *width, hard_end, &fpath, name)?;
            let start = frame.pos;
            let raw = &data[start..start + width];
            let stored = match width {
                1 => raw[0] as u64,
                _ => Endian::Big.read_u64(raw),
            };
            frame.pos = start + width;
            frame.placed.push(Node {
                kind: "checksum".to_string(),
                name: name.clone(),
                start,
                end: start + width,
                value: json!({ "int": stored, "hex": crate::hex::encode(raw) }),
                children: Vec::new(),
                present: true,
            });
            frame.pending.push(PendingChecksum {
                node_start: start,
                width: *width,
                algo: *algo,
                covers: covers.clone(),
                skip_self: *skip_self,
                mismatch: *mismatch,
            });
            Ok(())
        }
    }
}

fn fatal(code: &str, message: String, path: &[String], offset: usize) -> Stop {
    Stop {
        severity: Severity::Error,
        code: code.to_string(),
        message,
        path: path.to_vec(),
        offset,
        need_more: None,
    }
}

fn field_kind(field: &Field) -> &'static str {
    match field {
        Field::Int { .. } => "int",
        Field::Bytes { .. } => "bytes",
        Field::Payload { .. } => "payload",
        Field::Struct { .. } => "struct",
        Field::Ref { .. } => "ref",
        Field::Checksum { .. } => "checksum",
    }
}

/// 检查从 pos 起取 need 个字节是否可行。
/// 超出有界父结构 -> 违反协议；仅超出输入末端 -> incomplete 并给出下界。
fn require(
    data: &[u8],
    pos: usize,
    need: usize,
    hard_end: Option<usize>,
    path: &[String],
    fname: &str,
) -> Result<(), Stop> {
    if let Some(end) = hard_end {
        if pos.saturating_add(need) > end {
            return Err(Stop {
                severity: Severity::Error,
                code: "length_exceeds_parent".to_string(),
                message: format!(
                    "字段 '{fname}' 需要 {need} 个字节，超出父结构边界 {end}"
                ),
                path: path.to_vec(),
                offset: pos,
                need_more: None,
            });
        }
    }
    let available = data.len().saturating_sub(pos);
    if need > available {
        return Err(Stop {
            severity: Severity::Warning,
            code: "incomplete".to_string(),
            message: format!(
                "字段 '{fname}' 需要 {need} 个字节，当前仅有 {available} 个"
            ),
            path: path.to_vec(),
            offset: pos,
            need_more: Some(need - available),
        });
    }
    Ok(())
}

/// 解析变长字段长度，并保证长度不越过父结构边界。
fn resolve_length(
    len: &LengthOf,
    frame: &Frame,
    path: &[String],
    pos: usize,
) -> Result<(usize, Option<String>), Stop> {
    match len {
        LengthOf::Fixed { len } => Ok((*len, None)),
        LengthOf::Field { field, adjust } => {
            let node = frame
                .placed
                .iter()
                .rev()
                .find(|n| n.name == *field && n.present)
                .ok_or_else(|| {
                    fatal(
                        "length_field_missing",
                        format!("长度字段 '{field}' 尚未解析"),
                        path,
                        pos,
                    )
                })?;
            let raw = node
                .value
                .get("int")
                .and_then(Value::as_u64)
                .ok_or_else(|| {
                    fatal(
                        "length_field_bad_type",
                        format!("长度字段 '{field}' 不是整数"),
                        path,
                        node.start,
                    )
                })?;
            let length = (raw as i128 + *adjust as i128).max(0) as usize;
            Ok((length, Some(field.clone())))
        }
    }
}

fn conditions_hold(whens: &[When], frame: &Frame, path: &[String]) -> Result<bool, Stop> {
    for w in whens {
        let actual = lookup_value(&w.field, frame, path)?;
        if !compare(actual, w.op, &w.value) {
            return Ok(false);
        }
    }
    Ok(true)
}

fn lookup_value(field_path: &str, frame: &Frame, path: &[String]) -> Result<Value, Stop> {
    let parts: Vec<&str> = field_path.split('.').collect();
    let mut nodes: Vec<&Node> = frame
        .placed
        .iter()
        .filter(|n| n.present && n.name == parts[0])
        .collect();
    if nodes.is_empty() {
        return Err(fatal(
            "condition_field_missing",
            format!("条件引用的字段 '{}' 不存在", parts[0]),
            path,
            frame.pos,
        ));
    }
    for part in &parts[1..] {
        let current = nodes.pop().unwrap();
        let next = current
            .children
            .iter()
            .find(|c| c.present && c.name == *part)
            .ok_or_else(|| {
                fatal(
                    "condition_field_missing",
                    format!("条件路径 '{field_path}' 不存在"),
                    path,
                    frame.pos,
                )
            })?;
        nodes = vec![next];
    }
    Ok(nodes.pop().unwrap().value.clone())
}

fn compare(actual: Value, op: CondOp, want: &Value) -> bool {
    let to_u64 = |v: &Value| -> Option<u64> {
        v.get("int").and_then(Value::as_u64).or_else(|| json_as_u64(v))
    };
    if let (Some(a), Some(b)) = (to_u64(&actual), to_u64(want)) {
        return match op {
            CondOp::Eq => a == b,
            CondOp::Ne => a != b,
            CondOp::Lt => a < b,
            CondOp::Le => a <= b,
            CondOp::Gt => a > b,
            CondOp::Ge => a >= b,
        };
    }
    let a_str = actual
        .get("hex")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let b_str = want.as_str().unwrap_or("").to_string();
    match op {
        CondOp::Eq => a_str == b_str,
        CondOp::Ne => a_str != b_str,
        _ => false,
    }
}

fn verify_checksum(
    data: &[u8],
    placed: &mut [Node],
    pc: &PendingChecksum,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let cs_index = match placed
        .iter()
        .position(|n| n.start == pc.node_start && n.kind == "checksum")
    {
        Some(i) => i,
        None => return,
    };

    let mut ranges: Vec<(usize, usize)> = Vec::new();
    if pc.covers.is_empty() {
        // 覆盖整个父结构：从首个字段到当前校验和字段。
        if let (Some(first), Some(last)) = (placed.first(), placed.get(cs_index)) {
            ranges.push((first.start, last.end));
        }
    } else {
        for name in &pc.covers {
            if let Some(n) = placed.iter().find(|n| n.present && n.name == *name) {
                ranges.push((n.start, n.end));
            }
        }
    }

    let computed = {
        let cs_node = &placed[cs_index];
        compute_checksum(&ranges, pc, data, cs_node)
    };
    let stored = placed[cs_index]
        .value
        .get("int")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let ok = computed == stored;
    {
        let map = placed[cs_index].value.as_object_mut().unwrap();
        map.insert("verified".to_string(), json!(ok));
        map.insert("computed".to_string(), json!(computed));
    }
    if !ok {
        let cs_name = placed[cs_index].name.clone();
        let cs_start = placed[cs_index].start;
        let severity = match pc.mismatch {
            Severity::Error => "error",
            Severity::Warning => "warning",
        };
        diagnostics.push(Diagnostic {
            severity: severity.to_string(),
            code: "checksum_mismatch".to_string(),
            message: format!(
                "校验和 '{cs_name}' 不匹配：帧中 0x{stored:0width$x}，计算值 0x{computed:0width$x}",
                width = pc.width * 2
            ),
            path: vec![cs_name],
            offset: cs_start,
            need_more: None,
        });
    }
}

fn compute_checksum(
    ranges: &[(usize, usize)],
    pc: &PendingChecksum,
    data: &[u8],
    cs_node: &Node,
) -> u64 {
    let skip = |start: usize, end: usize| -> Vec<(usize, usize)> {
        if !pc.skip_self {
            return vec![(start, end)];
        }
        let mut out = Vec::new();
        if cs_node.start >= end || cs_node.end <= start {
            out.push((start, end));
        } else {
            if cs_node.start > start {
                out.push((start, cs_node.start));
            }
            if cs_node.end < end {
                out.push((cs_node.end, end));
            }
        }
        out
    };

    let mut sum8: u64 = 0;
    let mut xor: u8 = 0;
    let mut sum16: u64 = 0;
    for (s, e) in ranges {
        for (rs, re) in skip(*s, *e) {
            for b in &data[rs..re] {
                sum8 = (sum8 + *b as u64) & 0xff;
                xor ^= b;
            }
        }
    }
    match pc.algo {
        ChecksumAlgo::Sum8 => sum8 & 0xff,
        ChecksumAlgo::Xor8 => xor as u64,
        ChecksumAlgo::Sum16Be => {
            // 16 位大端进位和；奇数尾字节补零低字节。
            let mut raw: Vec<u8> = Vec::new();
            for (s, e) in ranges {
                for (rs, re) in skip(*s, *e) {
                    raw.extend_from_slice(&data[rs..re]);
                }
            }
            if raw.len() % 2 == 1 {
                raw.push(0);
            }
            for pair in raw.chunks_exact(2) {
                sum16 = (sum16 + u16::from_be_bytes([pair[0], pair[1]]) as u64) & 0xffff;
            }
            sum16
        }
    }
}

/// 解析树结构摘要：用于会话确定性与导入导出比对。
pub fn tree_digest(node: &Node) -> String {
    fn walk(node: &Node, out: &mut String) {
        use std::fmt::Write;
        let _ = write!(
            out,
            "{}|{}|{}|{}|{}|{};",
            node.kind,
            node.name,
            node.start,
            node.end,
            node.present,
            serde_json::to_string(&node.value).unwrap_or_default()
        );
        for c in &node.children {
            walk(c, out);
        }
    }
    let mut s = String::new();
    walk(node, &mut s);
    crate::sha256::hex(s.as_bytes())
}

/// 找出第二棵树中相对第一棵发生变化（值或覆盖区间）的节点路径。
pub fn diff_paths(before: &Node, after: &Node) -> Vec<Vec<String>> {
    fn index(node: &Node, path: &[String], map: &mut std::collections::BTreeMap<String, (usize, usize, String)>) {
        let key = path.join("/");
        map.insert(
            key,
            (
                node.start,
                node.end,
                serde_json::to_string(&node.value).unwrap_or_default(),
            ),
        );
        for c in &node.children {
            let mut p = path.to_vec();
            p.push(c.name.clone());
            index(c, &p, map);
        }
    }
    let mut map_before = std::collections::BTreeMap::new();
    let mut map_after = std::collections::BTreeMap::new();
    index(before, &[before.name.clone()], &mut map_before);
    index(after, &[after.name.clone()], &mut map_after);

    let mut changed = Vec::new();
    for (key, after_val) in &map_after {
        let is_changed = map_before
            .get(key)
            .map(|before_val| before_val != after_val)
            .unwrap_or(true);
        if is_changed {
            changed.push(key.split('/').map(|s| s.to_string()).collect());
        }
    }
    changed
}

/// 深度优先收集覆盖某个字节偏移的最深字段路径。
pub fn deepest_path_at(node: &Node, offset: usize) -> Vec<String> {
    fn walk(node: &Node, path: &[String], offset: usize) -> Option<Vec<String>> {
        if !node.present || offset < node.start || offset >= node.end {
            return None;
        }
        let mut current = path.to_vec();
        current.push(node.name.clone());
        for c in &node.children {
            if let Some(found) = walk(c, &current, offset) {
                return Some(found);
            }
        }
        Some(current)
    }
    walk(node, &[], offset).unwrap_or_default()
}
