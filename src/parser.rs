//! 字节级帧解析器：每个字节都映射到解析树节点，并严格区分 incomplete 与 violation。

use std::collections::BTreeMap;

use crate::json::Json;
use crate::spec::{
    BoundaryRef, ChecksumAlg, Endian, FieldDef, FieldKind, LengthExpr, Protocol, Severity,
    StructDef,
};

#[derive(Debug, Clone)]
pub struct FieldNode {
    /// 稳定标识：点路径加数组下标，例如 `frame.body.items[2].value`。
    pub id: String,
    pub name: String,
    /// struct / array / int / bytes / string / checksum / rest。
    pub kind: String,
    pub start: usize,
    pub end: usize,
    pub value: Json,
    pub children: Vec<FieldNode>,
}

impl FieldNode {
    fn container(
        id: String,
        name: String,
        kind: &str,
        start: usize,
        end: usize,
        children: Vec<FieldNode>,
    ) -> Self {
        FieldNode { id, name, kind: kind.to_string(), start, end, value: Json::Null, children }
    }

    fn leaf(id: String, name: String, kind: &str, start: usize, end: usize, value: Json) -> Self {
        FieldNode { id, name, kind: kind.to_string(), start, end, value, children: Vec::new() }
    }

    pub fn to_json(&self) -> Json {
        let mut o = Json::obj();
        o.insert("id", Json::from_str_value(self.id.clone()));
        o.insert("name", Json::from_str_value(self.name.clone()));
        o.insert("kind", Json::from_str_value(self.kind.clone()));
        o.insert("start", Json::Int(self.start as i64));
        o.insert("end", Json::Int(self.end as i64));
        o.insert("value", self.value.clone());
        o.insert(
            "children",
            Json::Array(self.children.iter().map(FieldNode::to_json).collect()),
        );
        o
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Complete,
    Incomplete,
    Error,
}

impl Outcome {
    fn label(&self) -> &'static str {
        match self {
            Outcome::Complete => "complete",
            Outcome::Incomplete => "incomplete",
            Outcome::Error => "error",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Incomplete {
    pub path: String,
    pub offset: usize,
    /// 仍需字节数的下界（至少还缺多少）。
    pub need_at_least: usize,
    pub reason: String,
}

#[derive(Debug, Clone)]
pub struct Violation {
    pub code: String,
    pub path: String,
    pub offset: usize,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct Warning {
    pub code: String,
    pub path: String,
    pub offset: usize,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct ParseResult {
    pub outcome: Outcome,
    pub root: Option<FieldNode>,
    pub consumed: usize,
    pub incomplete: Option<Incomplete>,
    pub violation: Option<Violation>,
    pub warnings: Vec<Warning>,
    pub input_len: usize,
}

impl ParseResult {
    /// 解析树摘要：把结果确定性序列化后取 SHA-256，导入导出时用于比对。
    pub fn tree_digest(&self) -> String {
        let mut summary = Json::obj();
        summary.insert("outcome", Json::from_str_value(self.outcome.label()));
        summary.insert("input_len", Json::Int(self.input_len as i64));
        summary.insert("consumed", Json::Int(self.consumed as i64));
        summary.insert(
            "tree",
            self.root.as_ref().map(FieldNode::to_json).unwrap_or(Json::Null),
        );
        summary.insert("violation", violation_json(self.violation.as_ref()));
        summary.insert("incomplete", incomplete_json(self.incomplete.as_ref()));
        summary.insert(
            "warnings",
            Json::Array(
                self.warnings
                    .iter()
                    .map(|w| {
                        let mut d = Json::obj();
                        d.insert("code", Json::from_str_value(w.code.clone()));
                        d.insert("path", Json::from_str_value(w.path.clone()));
                        d.insert("offset", Json::Int(w.offset as i64));
                        d.insert("message", Json::from_str_value(w.message.clone()));
                        d
                    })
                    .collect(),
            ),
        );
        crate::hash::hex_encode(&crate::hash::sha256(summary.stringify().as_bytes()))
    }
}

fn violation_json(v: Option<&Violation>) -> Json {
    match v {
        Some(v) => {
            let mut d = Json::obj();
            d.insert("code", Json::from_str_value(v.code.clone()));
            d.insert("path", Json::from_str_value(v.path.clone()));
            d.insert("offset", Json::Int(v.offset as i64));
            d.insert("message", Json::from_str_value(v.message.clone()));
            d
        }
        None => Json::Null,
    }
}

fn incomplete_json(i: Option<&Incomplete>) -> Json {
    match i {
        Some(i) => {
            let mut d = Json::obj();
            d.insert("path", Json::from_str_value(i.path.clone()));
            d.insert("offset", Json::Int(i.offset as i64));
            d.insert("need_at_least", Json::Int(i.need_at_least as i64));
            d.insert("reason", Json::from_str_value(i.reason.clone()));
            d
        }
        None => Json::Null,
    }
}

pub fn parse(protocol: &Protocol, data: &[u8]) -> ParseResult {
    let root_name = protocol.root.clone();
    let root_def = protocol.structs.get(&root_name).expect("编译期保证根结构存在");
    let mut engine = Engine { protocol, data, warnings: Vec::new() };
    let mut cursor = 0usize;
    let root_frame = Frame {
        id: root_name.clone(),
        display: root_name,
        start: 0,
        limit: None,
        depth: 1,
    };
    let mut chain = Vec::new();
    match engine.parse_struct(root_def, &root_frame, &mut cursor, &BTreeMap::new(), &mut chain) {
        Ok(node) if node.end < data.len() => ParseResult {
            outcome: Outcome::Error,
            consumed: node.end,
            root: Some(node.clone()),
            incomplete: None,
            violation: Some(Violation {
                code: "trailing_bytes".to_string(),
                path: node.id,
                offset: node.end,
                message: format!(
                    "根结构在字节 {} 结束，剩余 {} 字节未被任何字段消费",
                    node.end,
                    data.len() - node.end
                ),
            }),
            warnings: engine.warnings,
            input_len: data.len(),
        },
        Ok(node) => ParseResult {
            outcome: Outcome::Complete,
            consumed: node.end,
            root: Some(node),
            incomplete: None,
            violation: None,
            warnings: engine.warnings,
            input_len: data.len(),
        },
        Err(stop) => stop.into_result(engine.warnings, data.len()),
    }
}

#[derive(Debug, Clone)]
struct Frame {
    id: String,
    display: String,
    start: usize,
    /// Some(end)：声明了字节边界，越界即协议错误；None：沿用父结构空间。
    limit: Option<usize>,
    depth: u32,
    /// 本结构中，当前字段之后仍需保留的定长字段宽度（用于识破“假装截断”的恶意长度）。
    trailing_min: usize,
}

#[derive(Clone)]
struct PartialFrame {
    frame: Frame,
    siblings: Vec<FieldNode>,
    cursor: usize,
}

enum Stop {
    Incomplete { info: Incomplete, chain: Vec<PartialFrame> },
    Violation { violation: Violation, chain: Vec<PartialFrame> },
}

impl Stop {
    fn into_result(self, warnings: Vec<Warning>, input_len: usize) -> ParseResult {
        match self {
            Stop::Incomplete { info, chain } => {
                let root = rebuild(chain);
                ParseResult {
                    outcome: Outcome::Incomplete,
                    consumed: root.end,
                    root: Some(root),
                    incomplete: Some(info),
                    violation: None,
                    warnings,
                    input_len,
                }
            }
            Stop::Violation { violation, chain } => {
                let root = rebuild(chain);
                ParseResult {
                    outcome: Outcome::Error,
                    consumed: root.end,
                    root: Some(root),
                    incomplete: None,
                    violation: Some(violation),
                    warnings,
                    input_len,
                }
            }
        }
    }
}

/// chain 按从根到当前帧排列；最深层的失败字段尚未进入兄弟列表，用其 cursor 截断。
fn rebuild(mut chain: Vec<PartialFrame>) -> FieldNode {
    let mut current: Option<FieldNode> = None;
    while let Some(part) = chain.pop() {
        let mut children = part.siblings;
        if let Some(node) = current.take() {
            children.push(node);
        }
        current = Some(FieldNode::container(
            part.frame.id,
            part.frame.display,
            "struct",
            part.frame.start,
            part.cursor,
            children,
        ));
    }
    current.unwrap_or_else(|| {
        FieldNode::container(String::new(), String::new(), "struct", 0, 0, Vec::new())
    })
}

struct Engine<'a> {
    protocol: &'a Protocol,
    data: &'a [u8],
    warnings: Vec<Warning>,
}

type Out = Result<FieldNode, Stop>;

impl<'a> Engine<'a> {
    fn parse_field(
        &mut self,
        field: &FieldDef,
        id: &str,
        limit: Option<usize>,
        depth: u32,
        cursor: &mut usize,
        known: &BTreeMap<String, i64>,
        chain: &mut Vec<PartialFrame>,
    ) -> Out {
        let start = *cursor;
        match &field.kind {
            FieldKind::Int { width, signed, endian, expect } => self.parse_int(
                id,
                field,
                start,
                *width,
                *signed,
                *endian,
                *expect,
                cursor,
                chain,
            ),
            FieldKind::Bytes { length } => {
                let n = self.resolve_length(length, known, id, start, chain)?;
                self.take_slice(id, field, "bytes", start, n, cursor, limit, chain, false)
            }
            FieldKind::String_ { length } => {
                let n = self.resolve_length(length, known, id, start, chain)?;
                self.take_slice(id, field, "string", start, n, cursor, limit, chain, true)
            }
            FieldKind::Struct { struct_name, length, max_depth } => self.parse_nested_struct(
                id, field, struct_name, length.as_ref(), *max_depth, start, cursor, known,
                limit, depth, frame.trailing_min, chain,
            ),
            FieldKind::Array { item, count } => {
                let n = self.resolve_length(count, known, id, start, chain)?;
                self.parse_array(
                    id, field, item, n, start, cursor, known, limit, depth, frame.trailing_min, chain,
                )
            }
            FieldKind::Rest => self.parse_rest(id, field, start, cursor, limit, chain),
            FieldKind::Checksum { alg, .. } => self.take_slice(
                id,
                field,
                "checksum",
                start,
                alg.width(),
                cursor,
                limit,
                chain,
                false,
            ),
        }
    }

    fn need_bytes(
        &self,
        chain: &[PartialFrame],
        id: &str,
        cursor: usize,
        count: usize,
        what: &str,
    ) -> Stop {
        let available = self.data.len().saturating_sub(cursor);
        let needed = count.saturating_sub(available);
        Stop::Incomplete {
            info: Incomplete {
                path: id.to_string(),
                offset: cursor,
                need_at_least: needed,
                reason: format!("{what} 需要 {count} 字节，至少还缺 {needed} 字节"),
            },
            chain: chain.to_vec(),
        }
    }

    fn parse_int(
        &self,
        id: &str,
        field: &FieldDef,
        start: usize,
        width: u8,
        signed: bool,
        endian: Endian,
        expect: Option<i64>,
        cursor: &mut usize,
        chain: &mut Vec<PartialFrame>,
    ) -> Out {
        let count = width as usize;
        if self.data.len() < start + count {
            return Err(self.need_bytes(chain, id, start, count, "整数字段"));
        }
        let slice = &self.data[start..start + count];
        let raw = match endian {
            Endian::Big => match width {
                1 => slice[0] as u64,
                2 => u16::from_be_bytes([slice[0], slice[1]]) as u64,
                3 => ((slice[0] as u64) << 16) | ((slice[1] as u64) << 8) | slice[2] as u64,
                _ => u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]) as u64,
            },
            Endian::Little => match width {
                1 => slice[0] as u64,
                2 => u16::from_le_bytes([slice[0], slice[1]]) as u64,
                3 => (slice[0] as u64) | ((slice[1] as u64) << 8) | ((slice[2] as u64) << 16),
                _ => u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]) as u64,
            },
        };
        let value = if signed {
            let bits = (width as u32) * 8;
            let sign = 1u64 << (bits - 1);
            if raw & sign != 0 {
                (raw as i64) - (1i64 << (bits - 1)) * 2
            } else {
                raw as i64
            }
        } else {
            raw as i64
        };
        *cursor = start + count;
        if let Some(want) = expect {
            if value != want {
                return Err(Stop::Violation {
                    violation: Violation {
                        code: "expect_mismatch".to_string(),
                        path: id.to_string(),
                        offset: start,
                        message: format!(
                            "字段 `{}` 的常量断言失败：读到 {value}，协议要求 {want}",
                            field.name
                        ),
                    },
                    chain: chain.clone(),
                });
            }
        }
        Ok(FieldNode::leaf(
            id.to_string(),
            field.name.clone(),
            "int",
            start,
            *cursor,
            Json::Int(value),
        ))
    }

    fn parse_struct(
        &mut self,
        def: &StructDef,
        frame: &Frame,
        cursor: &mut usize,
        inherited: &BTreeMap<String, i64>,
        chain: &mut Vec<PartialFrame>,
    ) -> Out {
        let mut siblings = Vec::new();
        let mut known = inherited.clone();
        let mut spans: BTreeMap<String, (usize, usize)> = BTreeMap::new();
        let mut frame = frame.clone();
        frame.trailing_min = trailing_width_after(&def.fields, def.fields.len());
        chain.push(PartialFrame { frame: frame.clone(), siblings: Vec::new(), cursor: *cursor });
        let my_index = chain.len() - 1;

        if let Err(stop) = self.parse_fields(
            def, &mut frame, cursor, chain, &mut siblings, &mut known, &mut spans,
        ) {
            chain[my_index].siblings = siblings;
            chain[my_index].cursor = *cursor;
            return Err(stop);
        }

        let end = *cursor;
        if let Some(limit) = frame.limit {
            if end > limit {
                chain[my_index].siblings = siblings;
                chain[my_index].cursor = end;
                return Err(Stop::Violation {
                    violation: Violation {
                        code: "length_out_of_bounds".to_string(),
                        path: frame.id.clone(),
                        offset: limit,
                        message: format!(
                            "结构 `{}` 解析到字节 {end}，超出长度字段声明的边界 {limit}",
                            frame.display
                        ),
                    },
                    chain: chain.clone(),
                });
            }
        }
        chain.pop();
        Ok(FieldNode::container(
            frame.id.clone(),
            frame.display.clone(),
            "struct",
            frame.start,
            end,
            siblings,
        ))
    }

    /// 当前结构已解析的字段之后，仍要出现的“无条件定长”字段宽度和；
    /// 条件字段与变长字段忽略（下界）。
    fn update_trailing(&self, def: &StructDef, field_index: usize, frame: &mut Frame) {
        frame.trailing_min = trailing_width_after(&def.fields, field_index + 1);
    }

    #[allow(clippy::too_many_arguments)]
    fn parse_fields(
        &mut self,
        def: &StructDef,
        frame: &mut Frame,
        cursor: &mut usize,
        chain: &mut Vec<PartialFrame>,
        siblings: &mut Vec<FieldNode>,
        known: &mut BTreeMap<String, i64>,
        spans: &mut BTreeMap<String, (usize, usize)>,
    ) -> Result<(), Stop> {
        for (field_index, field) in def.fields.iter().enumerate() {
            if let Some(when) = &field.when {
                if !when.holds(known) {
                    continue;
                }
            }
            frame.trailing_min = trailing_width_after(&def.fields, field_index + 1);
            let child_id = format!("{}.{}", frame.id, field.name);
            let node = self.parse_field(
                field,
                &child_id,
                frame.limit,
                frame.depth,
                cursor,
                known,
                chain,
            )?;
            if let Json::Int(n) = &node.value {
                known.insert(node.name.clone(), *n);
            }
            spans.insert(node.name.clone(), (node.start, node.end));
            if let FieldKind::Checksum { alg, from, to, skip_self, severity } = &field.kind {
                if let Some(v) =
                    self.evaluate_checksum(&node, *alg, from, to, *skip_self, *severity, frame, spans)
                {
                    siblings.push(node);
                    let my_index = chain.len() - 1;
                    chain[my_index].siblings = std::mem::take(siblings);
                    chain[my_index].cursor = *cursor;
                    return Err(Stop::Violation {
                        violation: v,
                        chain: chain.clone(),
                    });
                }
            }
            siblings.push(node);
        }
        Ok(())
    }

    fn resolve_length(
        &self,
        expr: &LengthExpr,
        known: &BTreeMap<String, i64>,
        id: &str,
        offset: usize,
        chain: &mut Vec<PartialFrame>,
    ) -> Result<usize, Stop> {
        let raw = match expr {
            LengthExpr::Fixed(n) => *n,
            LengthExpr::Field { name, scale, offset: add } => {
                let base = known.get(name).copied().ok_or_else(|| Stop::Violation {
                    violation: Violation {
                        code: "length_reference_missing".to_string(),
                        path: id.to_string(),
                        offset,
                        message: format!("长度表达式引用的字段 `{name}` 当前没有整数值"),
                    },
                    chain: chain.clone(),
                })?;
                base.checked_mul(*scale)
                    .and_then(|v| v.checked_add(*add))
                    .ok_or_else(|| Stop::Violation {
                        violation: Violation {
                            code: "length_overflow".to_string(),
                            path: id.to_string(),
                            offset,
                            message: "长度表达式发生整数溢出".to_string(),
                        },
                        chain: chain.clone(),
                    })?
            }
        };
        if raw < 0 {
            return Err(Stop::Violation {
                violation: Violation {
                    code: "negative_length".to_string(),
                    path: id.to_string(),
                    offset,
                    message: format!("长度表达式计算结果为 {raw}，长度不能为负"),
                },
                chain: chain.clone(),
            });
        }
        Ok(raw as usize)
    }

    fn take_slice(
        &self,
        id: &str,
        field: &FieldDef,
        kind: &str,
        start: usize,
        count: usize,
        cursor: &mut usize,
        limit: Option<usize>,
        chain: &mut Vec<PartialFrame>,
        decode_utf8: bool,
    ) -> Out {
        if let Some(limit) = limit {
            let end = start.checked_add(count);
            if end.map(|e| e > limit).unwrap_or(true) {
                return Err(Stop::Violation {
                    violation: Violation {
                        code: "length_out_of_bounds".to_string(),
                        path: id.to_string(),
                        offset: start,
                        message: format!(
                            "字段 `{}` 声明 {count} 字节，会越过父结构边界 {limit}",
                            field.name
                        ),
                    },
                    chain: chain.clone(),
                });
            }
        }
        if self.data.len() < start + count {
            let what = if kind == "checksum" {
                "校验字段"
            } else if kind == "string" {
                "字符串字段"
            } else {
                "字节字段"
            };
            return Err(self.need_bytes(chain, id, start, count, what));
        }
        let slice = &self.data[start..start + count];
        *cursor = start + count;
        let value = if decode_utf8 {
            match std::str::from_utf8(slice) {
                Ok(s) => Json::from_str_value(s),
                Err(_) => {
                    let mut o = Json::obj();
                    o.insert("hex", Json::from_str_value(crate::bytes::to_hex(slice)));
                    o.insert("utf8_error", Json::Bool(true));
                    o
                }
            }
        } else {
            Json::from_str_value(crate::bytes::to_hex(slice))
        };
        Ok(FieldNode::leaf(
            id.to_string(),
            field.name.clone(),
            kind,
            start,
            *cursor,
            value,
        ))
    }

    fn parse_rest(
        &self,
        id: &str,
        field: &FieldDef,
        start: usize,
        cursor: &mut usize,
        limit: Option<usize>,
        chain: &mut Vec<PartialFrame>,
    ) -> Out {
        let end = limit.unwrap_or(self.data.len());
        if end < start {
            return Err(Stop::Violation {
                violation: Violation {
                    code: "rest_before_start".to_string(),
                    path: id.to_string(),
                    offset: start,
                    message: "rest 字段起点越过了父结构边界".to_string(),
                },
                chain: chain.clone(),
            });
        }
        *cursor = end;
        Ok(FieldNode::leaf(
            id.to_string(),
            field.name.clone(),
            "rest",
            start,
            end,
            Json::from_str_value(crate::bytes::to_hex(&self.data[start..end])),
        ))
    }

    fn parse_nested_struct(
        &mut self,
        id: &str,
        field: &FieldDef,
        struct_name: &str,
        length: Option<&LengthExpr>,
        max_depth: u32,
        start: usize,
        cursor: &mut usize,
        known: &BTreeMap<String, i64>,
        parent_limit: Option<usize>,
        parent_depth: u32,
        chain: &mut Vec<PartialFrame>,
    ) -> Out {
        let child_def = match self.protocol.structs.get(struct_name) {
            Some(d) => d,
            None => {
                return Err(Stop::Violation {
                    violation: Violation {
                        code: "unknown_struct".to_string(),
                        path: id.to_string(),
                        offset: start,
                        message: format!("引用了未声明的结构 `{struct_name}`"),
                    },
                    chain: chain.clone(),
                })
            }
        };
        let limit = match length {
            Some(expr) => {
                let n = self.resolve_length(expr, known, id, start, chain)?;
                let end = start.checked_add(n).ok_or_else(|| Stop::Violation {
                    violation: Violation {
                        code: "length_overflow".to_string(),
                        path: id.to_string(),
                        offset: start,
                        message: "子结构长度导致偏移溢出".to_string(),
                    },
                    chain: chain.clone(),
                })?;
                if let Some(parent_limit) = parent_limit {
                    if end > parent_limit {
                        return Err(Stop::Violation {
                            violation: Violation {
                                code: "length_out_of_bounds".to_string(),
                                path: id.to_string(),
                                offset: start,
                                message: format!(
                                    "子结构 `{struct_name}` 的声明长度越过父结构边界 {parent_limit}"
                                ),
                            },
                            chain: chain.clone(),
                        });
                    }
                }
                if self.data.len() < end {
                    // 声明的子结构末端越过实际输入。若父结构在此字段之后仍有
                    // 定长字段（trailing_min）且整体输入也放不下，说明长度在撒谎，
                    // 而不是“样本尚未传完”。
                    if start
                        .checked_add(n)
                        .map(|claimed| claimed + trailing_min_at(known, parent_limit, frame_trailing))
                        .map(|needed| needed > self.data.len())
                        .unwrap_or(true)
                        && frame_trailing > 0
                    {
                        return Err(Stop::Violation {
                            violation: Violation {
                                code: "length_beyond_input".to_string(),
                                path: id.to_string(),
                                offset: start,
                                message: format!(
                                    "字段声明长度 {n}，连同后续 {frame_trailing} 个定长字节已超出输入，属于恶意长度而非截断"
                                ),
                            },
                            chain: chain.clone(),
                        });
                    }
                    return Err(self.need_bytes(chain, id, start, n, "有界子结构"));
                }
                Some(end)
            }
            None => parent_limit,
        };
        let depth = parent_depth + 1;
        if depth > max_depth {
            return Err(Stop::Violation {
                violation: Violation {
                    code: "recursion_limit".to_string(),
                    path: id.to_string(),
                    offset: start,
                    message: format!("递归结构 `{struct_name}` 超过深度上限 {max_depth}"),
                },
                chain: chain.clone(),
            });
        }
        let child_frame = Frame {
            id: id.to_string(),
            display: struct_name.to_string(),
            start,
            limit,
            depth,
        };
        let child_known = BTreeMap::new();
        let mut node =
            self.parse_struct(child_def, &child_frame, cursor, &child_known, chain)?;
        node.name = field.name.clone();
        Ok(node)
    }

    fn parse_array(
        &mut self,
        id: &str,
        field: &FieldDef,
        item: &FieldDef,
        count: usize,
        start: usize,
        cursor: &mut usize,
        known: &BTreeMap<String, i64>,
        parent_limit: Option<usize>,
        depth: u32,
        chain: &mut Vec<PartialFrame>,
    ) -> Out {
        let array_frame = Frame {
            id: id.to_string(),
            display: field.name.clone(),
            start,
            limit: parent_limit,
            depth,
        };
        let mut children = Vec::with_capacity(count);
        for index in 0..count {
            let item_id = format!("{id}[{index}]");
            match self.parse_field(item, &item_id, parent_limit, depth, cursor, known, chain) {
                Ok(node) => children.push(node),
                Err(stop) => {
                    return Err(insert_array_frame(
                        stop,
                        &array_frame,
                        std::mem::take(&mut children),
                        *cursor,
                    ))
                }
            }
        }
        Ok(FieldNode::container(
            id.to_string(),
            field.name.clone(),
            "array",
            start,
            *cursor,
            children,
        ))
    }

    fn evaluate_checksum(
        &mut self,
        node: &FieldNode,
        alg: ChecksumAlg,
        from: &BoundaryRef,
        to: &BoundaryRef,
        skip_self: bool,
        severity: Severity,
        frame: &Frame,
        spans: &BTreeMap<String, (usize, usize)>,
    ) -> Option<Violation> {
        let data_len = self.data.len();
        let frame_end = frame.limit.unwrap_or(data_len);
        let from_pos = match from {
            BoundaryRef::Start => frame.start,
            BoundaryRef::End => frame_end,
            BoundaryRef::Field(name) => match spans.get(name) {
                Some((s, _)) => *s,
                None => {
                    self.warnings.push(Warning {
                        code: "checksum_boundary_missing".to_string(),
                        path: node.id.clone(),
                        offset: node.start,
                        message: format!("校验区间起点字段 `{name}` 尚无字节区间，跳过校验"),
                    });
                    return None;
                }
            },
        };
        let to_pos = match to {
            BoundaryRef::Start => frame.start,
            BoundaryRef::End => frame_end,
            BoundaryRef::Field(name) => match spans.get(name) {
                Some((_, e)) => *e,
                None => {
                    self.warnings.push(Warning {
                        code: "checksum_boundary_missing".to_string(),
                        path: node.id.clone(),
                        offset: node.start,
                        message: format!("校验区间终点字段 `{name}` 尚无字节区间，跳过校验"),
                    });
                    return None;
                }
            },
        };
        // skip_self + eoi：覆盖区在 checksum 字段处自然结束，末端取字段起点。
        let to_eff = if skip_self && matches!(to, BoundaryRef::End) && frame.limit.is_none() {
            node.start
        } else {
            to_pos
        };
        if from_pos > to_eff || to_eff > data_len {
            self.warnings.push(Warning {
                code: "checksum_range_invalid".to_string(),
                path: node.id.clone(),
                offset: node.start,
                message: format!("校验区间 [{from_pos},{to_eff}) 反向或超出输入长度，跳过校验"),
            });
            return None;
        }
        let mut covered = Vec::new();
        if skip_self {
            covered.extend_from_slice(&self.data[from_pos..node.start.min(to_eff)]);
            covered.extend_from_slice(&self.data[node.end.min(to_eff)..to_eff]);
        } else {
            covered.extend_from_slice(&self.data[from_pos..to_eff]);
        }
        let computed = compute_checksum(alg, &covered);
        let actual = &self.data[node.start..node.end];
        if actual == computed.as_slice() {
            return None;
        }
        let message = format!(
            "{} 校验失败：区间 [{from_pos},{to_pos}){} 计算为 {}，帧内为 {}",
            alg.name(),
            if skip_self { "（跳过自身字段）" } else { "" },
            crate::bytes::to_hex(&computed),
            crate::bytes::to_hex(actual)
        );
        match severity {
            Severity::Warn => {
                self.warnings.push(Warning {
                    code: "checksum_mismatch".to_string(),
                    path: node.id.clone(),
                    offset: node.start,
                    message,
                });
                None
            }
            Severity::Error => Some(Violation {
                code: "checksum_mismatch".to_string(),
                path: node.id.clone(),
                offset: node.start,
                message,
            }),
        }
    }
}

fn insert_array_frame(
    mut stop: Stop,
    frame: &Frame,
    children: Vec<FieldNode>,
    cursor: usize,
) -> Stop {
    // 数组帧比结构帧“更浅”于失败元素内部的结构帧，因此插到 chain 头部，
    // rebuild 从尾部弹出时顺序为 根..结构..数组..失败元素结构。
    match &mut stop {
        Stop::Incomplete { chain, .. } | Stop::Violation { chain, .. } => {
            chain.insert(
                0,
                PartialFrame { frame: frame.clone(), siblings: children, cursor },
            );
        }
    }
    stop
}

/// 从字段索引 `from` 起，无条件出现的定宽字段宽度和（变长/条件字段贡献 0）。
fn trailing_width_after(fields: &[FieldDef], from: usize) -> usize {
    fields[from.min(fields.len())..]
        .iter()
        .filter(|f| f.when.is_none())
        .map(|f| match &f.kind {
            FieldKind::Int { width, .. } => *width as usize,
            FieldKind::Checksum { alg, .. } => alg.width(),
            _ => 0,
        })
        .sum()
}

fn compute_checksum(alg: ChecksumAlg, data: &[u8]) -> Vec<u8> {
    match alg {
        // sum8 采用“覆盖区与校验字节相加后低 8 位为 0”的补码约定。
        ChecksumAlg::Sum8 => vec![(0u8).wrapping_sub(data.iter().fold(0u8, |a, b| a.wrapping_add(*b)))],
        ChecksumAlg::Xor8 => vec![data.iter().fold(0u8, |a, b| a ^ *b)],
        ChecksumAlg::Sum16Be => {
            let s = data
                .chunks(2)
                .fold(0u16, |acc, chunk| {
                    if chunk.len() == 2 {
                        acc.wrapping_add(u16::from_be_bytes([chunk[0], chunk[1]]))
                    } else {
                        acc.wrapping_add((chunk[0] as u16) << 8)
                    }
                });
            s.to_be_bytes().to_vec()
        }
    }
}

/// 供数据生成器使用：单字节校验的“合法帧补码”。
pub fn checksum_fix_byte(alg: ChecksumAlg, covered: &[u8]) -> u8 {
    match alg {
        ChecksumAlg::Sum8 => {
            let s = covered.iter().fold(0u8, |a, b| a.wrapping_add(*b));
            (0u8).wrapping_sub(s)
        }
        ChecksumAlg::Xor8 => covered.iter().fold(0u8, |a, b| a ^ *b),
        ChecksumAlg::Sum16Be => panic!("sum16be 请用 checksum_fix_u16"),
    }
}

pub fn checksum_fix_u16(covered: &[u8]) -> [u8; 2] {
    let s = covered.iter().fold(0u16, |a, b| a.wrapping_add(*b as u16));
    (0u16).wrapping_sub(s).to_be_bytes()
}
