//! 解析引擎：字节流 + 编译协议 -> 解析树 / incomplete / error。
//!
//! 即使失败也会返回“目前为止”的部分树，最深失败点由 Diag.path/offset 给出。

use crate::eval::{eval_bool, eval_usize, resolve_bound, Scope, Val};
use crate::json::Json;
use crate::model::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    Complete,
    Incomplete,
    Error,
}

#[derive(Debug, Clone)]
pub struct Diag {
    pub kind: String,
    pub path: Vec<String>,
    pub offset: usize,
    pub message: String,
    /// incomplete：仍需字节数下界
    pub need: Option<usize>,
}

#[derive(Debug, Clone, Default)]
pub struct Node {
    pub name: String,
    pub kind: String,
    pub start: usize,
    pub end: usize,
    pub value: Option<String>,
    pub numeric: Option<u64>,
    pub status: String,
    pub note: Option<String>,
    pub children: Vec<Node>,
    pub depth: usize,
}

#[derive(Debug, Clone)]
pub struct ParseOut {
    pub status: String,
    pub tree: Node,
    pub diag: Option<Diag>,
    pub warnings: Vec<Diag>,
}

enum Stop {
    /// 正常结束，返回消耗后的位置
    Ok(usize),
    /// 输入不完整，至少还需 n 字节
    Need(usize, Node),
    /// 协议违反：错误信息、字节偏移、节点路径、未完成节点
    Fail(String, usize, Vec<String>, Node),
}

struct Frame {
    pos: usize,
    struct_start: usize,
    scope: Scope,
    children: Vec<Node>,
    /// 区域硬边界（None 表示无界）
    hard_end: Option<usize>,
    depth: usize,
    path: Vec<String>,
}

struct Engine<'a> {
    p: &'a Protocol,
    data: &'a [u8],
    warnings: Vec<Diag>,
}

fn int_value(data: &[u8], kind: IntKind, start: usize) -> u64 {
    let w = kind.width();
    let mut v = 0u64;
    match kind {
        IntKind::U8 | IntKind::U16Be | IntKind::U24Be | IntKind::U32Be => {
            for i in 0..w {
                v = (v << 8) | data[start + i] as u64;
            }
        }
        IntKind::U16Le | IntKind::U32Le => {
            for i in (0..w).rev() {
                v = (v << 8) | data[start + i] as u64;
            }
        }
    }
    v
}

/// 需要读取 n 字节时的判定：硬边界违规优先于 incomplete。
fn ensure(
    fr: &Frame,
    data_len: usize,
    n: usize,
    node: Node,
) -> Result<(), Stop> {
    if let Some(end) = fr.hard_end {
        if fr.pos + n > end {
            return Err(Stop::Fail(
                format!("字段需要 {} 字节，越过父结构边界 {}", n, end),
                fr.pos,
                fr.path.clone(),
                node,
            ));
        }
    }
    if fr.pos + n > data_len {
        let need = fr.pos + n - data_len;
        return Err(Stop::Need(need, node));
    }
    Ok(())
}

pub fn parse(p: &Protocol, data: &[u8]) -> ParseOut {
    let mut eng = Engine {
        p,
        data,
        warnings: Vec::new(),
    };
    let root_def = p.find(&p.root).expect("compile 保证 root 存在");
    let mut fr = Frame {
        pos: 0,
        struct_start: 0,
        scope: Scope::default(),
        children: Vec::new(),
        hard_end: None,
        depth: 0,
        path: vec![p.root.clone()],
    };

    let (status, diag, root_end) = match eng.parse_struct(root_def, &mut fr) {
        Stop::Ok(end) => {
            if end < data.len() {
                eng.warnings.push(Diag {
                    kind: "trailing_bytes".into(),
                    path: vec![p.root.clone()],
                    offset: end,
                    message: format!("根结构后仍有 {} 个未解析字节", data.len() - end),
                    need: None,
                });
            }
            ("complete", None, end)
        }
        Stop::Need(n, _) => (
            "incomplete",
            Some(Diag {
                kind: "incomplete".into(),
                path: deepest_path(&fr.children),
                offset: data.len(),
                message: format!("输入尚未完整，至少还需 {} 个字节", n),
                need: Some(n),
            }),
            data.len(),
        ),
        Stop::Fail(msg, off, path, node) => {
            let _ = node;
            (
                "error",
                Some(Diag {
                    kind: "protocol_violation".into(),
                    path: if path.is_empty() { deepest_path(&fr.children) } else { path },
                    offset: off,
                    message: msg,
                    need: None,
                }),
                off,
            )
        }
    };

    let mut tree = Node {
        name: p.root.clone(),
        kind: "struct".to_string(),
        start: 0,
        end: root_end,
        status: status.to_string(),
        note: None,
        value: None,
        numeric: None,
        children: fr.children,
        depth: 0,
    };
    paint(&mut tree, status);

    ParseOut {
        status: status.to_string(),
        tree,
        diag,
        warnings: eng.warnings,
    }
}

fn paint(n: &mut Node, status: &str) {
    if n.status == "complete" {
        n.status = status.to_string();
    }
    for c in &mut n.children {
        paint(c, status);
    }
}

impl<'a> Engine<'a> {
    fn parse_struct(&mut self, def: &StructDef, fr: &mut Frame) -> Stop {
        for field in &def.fields {
            // 条件字段
            if let Some(w) = &field.when {
                let active = match eval_bool(w, &fr.scope, fr.pos) {
                    Ok(b) => b,
                    Err(e) => {
                        return Stop::Fail(
                            format!("字段 {} 条件求值失败：{}", field.name, e.message),
                            fr.pos,
                            self.child_path(fr, field),
                            Node {
                                name: field.name.clone(),
                                kind: self.kind_label(field),
                                start: fr.pos,
                                end: fr.pos,
                                status: "error".into(),
                                note: Some(e.message.clone()),
                                depth: fr.depth + 1,
                                ..Node::default()
                            },
                        );
                    }
                };
                if !active {
                    continue;
                }
            }

            let stop = self.parse_field(def, field, fr);
            match stop {
                Stop::Ok(_) => {}
                Stop::Need(n, node) => {
                    if node.name != field.name {
                        fr.children.push(node);
                    } else {
                        fr.children.push(node);
                    }
                    return Stop::Need(n, Node::default());
                }
                Stop::Fail(msg, off, path, node) => {
                    if node.name == field.name {
                        fr.children.push(node);
                    }
                    return Stop::Fail(msg, off, path, Node::default());
                }
            }
        }
        Stop::Ok(fr.pos)
    }

    fn kind_label(&self, field: &Field) -> String {
        match &field.kind {
            FieldKind::Int(_) => "int",
            FieldKind::FixedBytes(_) => "bytes",
            FieldKind::VarBytes(_) => "bytes",
            FieldKind::InlineStruct(_) => "struct",
            FieldKind::StructRef(_, _) => "struct",
            FieldKind::Repeat(_, _) => "repeat",
            FieldKind::Checksum(_) => "checksum",
            FieldKind::Assert(_) => "assert",
        }
        .to_string()
    }

    fn child_path(&self, fr: &Frame, field: &Field) -> Vec<String> {
        let mut p = fr.path.clone();
        p.push(field.name.clone());
        p
    }

    fn record_int(&self, fr: &mut Frame, name: &str, start: usize, end: usize, val: u64) {
        fr.scope.fields.push((
            name.to_string(),
            crate::eval::ResolvedField {
                value: val,
                start,
                end,
            },
        ));
    }
}

impl<'a> Engine<'a> {
    fn fail_node(&self, fr: &Frame, field: &Field, start: usize, msg: String) -> Node {
        Node {
            name: field.name.clone(),
            kind: self.kind_label(field),
            start,
            end: start,
            status: "error".into(),
            note: Some(msg.clone()),
            depth: fr.depth + 1,
            ..Node::default()
        }
    }

    fn parse_field(&mut self, def: &StructDef, field: &Field, fr: &mut Frame) -> Stop {
        match &field.kind {
            FieldKind::Int(kind) => {
                let w = kind.width();
                let start = fr.pos;
                let probe = Node::leaf_probe(field, start, fr.depth);
                if let Err(s) = ensure(fr, self.data.len(), w, probe) {
                    return s;
                }
                let val = int_value(self.data, *kind, start);
                let end = start + w;
                self.record_int(fr, &field.name, start, end, val);
                fr.pos = end;
                fr.children.push(Node {
                    name: field.name.clone(),
                    kind: format!("{:?}", kind).to_lowercase(),
                    start,
                    end,
                    value: Some(format!("{} (0x{:x})", val, val)),
                    numeric: Some(val),
                    status: "complete".into(),
                    note: None,
                    children: Vec::new(),
                    depth: fr.depth + 1,
                });
                Stop::Ok(end)
            }
            FieldKind::FixedBytes(n) => {
                let start = fr.pos;
                let probe = Node::leaf_probe(field, start, fr.depth);
                if let Err(s) = ensure(fr, self.data.len(), *n, probe) {
                    return s;
                }
                let end = start + n;
                fr.pos = end;
                fr.children.push(self.bytes_node(field, start, end, fr.depth + 1));
                Stop::Ok(end)
            }
            FieldKind::VarBytes(e) => {
                let n = match eval_usize(e, &fr.scope, fr.pos) {
                    Ok(n) => n,
                    Err(err) => {
                        return Stop::Fail(
                            format!("字段 {} 长度表达式失败：{}", field.name, err.message),
                            fr.pos,
                            self.child_path(fr, field),
                            self.fail_node(fr, field, fr.pos, err.message),
                        );
                    }
                };
                let start = fr.pos;
                let probe = Node::leaf_probe(field, start, fr.depth);
                if let Err(s) = ensure(fr, self.data.len(), n, probe) {
                    return s;
                }
                let end = start + n;
                fr.pos = end;
                fr.children.push(self.bytes_node(field, start, end, fr.depth + 1));
                Stop::Ok(end)
            }
            FieldKind::Assert(e) => {
                let start = fr.pos;
                match crate::eval::eval(e, &fr.scope, start) {
                    Ok(Val::Bool(true)) => {
                        fr.children.push(Node {
                            name: field.name.clone(),
                            kind: "assert".into(),
                            start,
                            end: start,
                            value: Some("true".into()),
                            status: "complete".into(),
                            depth: fr.depth + 1,
                            ..Node::default()
                        });
                        Stop::Ok(start)
                    }
                    Ok(Val::Bool(false)) => Stop::Fail(
                        format!("断言 {} 不成立", field.name),
                        start,
                        self.child_path(fr, field),
                        Node {
                            name: field.name.clone(),
                            kind: "assert".into(),
                            start,
                            end: start,
                            value: Some("false".into()),
                            status: "error".into(),
                            note: Some("常量/表达式断言失败".into()),
                            depth: fr.depth + 1,
                            ..Node::default()
                        },
                    ),
                    Ok(Val::Int(_)) => Stop::Fail(
                        format!("断言 {} 不是布尔表达式", field.name),
                        start,
                        self.child_path(fr, field),
                        self.fail_node(fr, field, start, "断言必须为布尔表达式".into()),
                    ),
                    Err(err) => Stop::Fail(
                        format!("断言 {} 求值失败：{}", field.name, err.message),
                        start,
                        self.child_path(fr, field),
                        self.fail_node(fr, field, start, err.message),
                    ),
                }
            }
            FieldKind::Checksum(spec) => self.parse_checksum(def, field, spec, fr),
            FieldKind::InlineStruct(inner) => self.parse_inline(field, inner, None, fr),
            FieldKind::StructRef(name, size) => {
                let inner = self
                    .p
                    .find(name)
                    .expect("compile 保证结构存在")
                    .clone();
                let size = match size {
                    Some(e) => match eval_usize(e, &fr.scope, fr.pos) {
                        Ok(n) => Some(n),
                        Err(err) => {
                            return Stop::Fail(
                                format!("字段 {} 长度表达式失败：{}", field.name, err.message),
                                fr.pos,
                                self.child_path(fr, field),
                                self.fail_node(fr, field, fr.pos, err.message),
                            );
                        }
                    },
                    None => None,
                };
                self.parse_named_ref(field, &inner, size, fr)
            }
            FieldKind::Repeat(count, body) => self.parse_repeat(field, count, body, fr),
        }
    }
}

impl Node {
    fn leaf_probe(field: &Field, start: usize, depth: usize) -> Node {
        Node {
            name: field.name.clone(),
            kind: field_kind_str(field),
            start,
            end: start,
            status: "incomplete".into(),
            depth: depth + 1,
            ..Node::default()
        }
    }
}

fn field_kind_str(field: &Field) -> String {
    match &field.kind {
        FieldKind::Int(k) => format!("{:?}", k).to_lowercase(),
        FieldKind::FixedBytes(_) | FieldKind::VarBytes(_) => "bytes".into(),
        FieldKind::InlineStruct(_) | FieldKind::StructRef(_, _) => "struct".into(),
        FieldKind::Repeat(_, _) => "repeat".into(),
        FieldKind::Checksum(_) => "checksum".into(),
        FieldKind::Assert(_) => "assert".into(),
    }
}

impl<'a> Engine<'a> {
    fn bytes_node(&self, field: &Field, start: usize, end: usize, depth: usize) -> Node {
        let hex = crate::hex::encode(&self.data[start..end]);
        let preview = if hex.len() > 64 {
            format!("{}…", &hex[..64])
        } else {
            hex
        };
        Node {
            name: field.name.clone(),
            kind: "bytes".into(),
            start,
            end,
            value: Some(preview),
            numeric: Some((end - start) as u64),
            status: "complete".into(),
            note: Some(format!("{} 字节", end - start)),
            depth,
            ..Node::default()
        }
    }

    fn parse_inline(
        &mut self,
        field: &Field,
        inner: &StructDef,
        size: Option<usize>,
        fr: &mut Frame,
    ) -> Stop {
        let start = fr.pos;
        // 定界检查（声明大小）
        if let Some(n) = size {
            let probe = Node {
                name: field.name.clone(),
                kind: "struct".into(),
                start,
                end: start,
                status: "incomplete".into(),
                depth: fr.depth + 1,
                ..Node::default()
            };
            if let Err(s) = ensure(fr, self.data.len(), n, probe) {
                return s;
            }
        }
        let hard_end = size.map(|n| start + n);
        let mut child = Frame {
            pos: start,
            struct_start: start,
            scope: Scope::default(),
            children: Vec::new(),
            hard_end,
            depth: fr.depth + 1,
            path: {
                let mut p = fr.path.clone();
                p.push(field.name.clone());
                p
            },
        };
        let result = self.parse_struct(inner, &mut child);
        match result {
            Stop::Ok(end) => {
                // 定界结构必须精确消耗
                if let Some(he) = hard_end {
                    if end != he {
                        let mut node = Node {
                            name: field.name.clone(),
                            kind: "struct".into(),
                            start,
                            end,
                            status: "error".into(),
                            note: Some(format!("定界结构未占满声明区间（剩余 {} 字节）", he - end)),
                            children: child.children,
                            depth: fr.depth + 1,
                            ..Node::default()
                        };
                        self.propagate(&mut node, "error");
                        return Stop::Fail(
                            format!("字段 {} 的定界区间未被完全消耗", field.name),
                            end,
                            child.path,
                            node,
                        );
                    }
                }
                fr.pos = end;
                fr.children.push(Node {
                    name: field.name.clone(),
                    kind: "struct".into(),
                    start,
                    end,
                    status: "complete".into(),
                    children: child.children,
                    depth: fr.depth + 1,
                    ..Node::default()
                });
                Stop::Ok(end)
            }
            Stop::Need(n, _node) => {
                fr.children.push(Node {
                    name: field.name.clone(),
                    kind: "struct".into(),
                    start,
                    end: child.pos,
                    status: "incomplete".into(),
                    children: child.children,
                    depth: fr.depth + 1,
                    ..Node::default()
                });
                fr.pos = child.pos;
                Stop::Need(n, Node::default())
            }
            Stop::Fail(msg, off, _path, _node) => {
                fr.children.push(Node {
                    name: field.name.clone(),
                    kind: "struct".into(),
                    start,
                    end: off,
                    status: "error".into(),
                    children: child.children,
                    depth: fr.depth + 1,
                    ..Node::default()
                });
                fr.pos = off;
                Stop::Fail(
                    msg,
                    off,
                    {
                        let mut p = fr.path.clone();
                        p.push(field.name.clone());
                        p
                    },
                    Node::default(),
                )
            }
        }
    }

    fn propagate(&self, n: &mut Node, status: &str) {
        if n.status == "complete" || n.status.is_empty() {
            n.status = status.to_string();
        }
        for c in &mut n.children {
            self.propagate(c, status);
        }
    }
}

impl<'a> Engine<'a> {
    fn parse_named_ref(
        &mut self,
        field: &Field,
        inner: &StructDef,
        size: Option<usize>,
        fr: &mut Frame,
    ) -> Stop {
        let start = fr.pos;
        if let Some(n) = size {
            let probe = Node {
                name: field.name.clone(),
                kind: "struct".into(),
                start,
                end: start,
                status: "incomplete".into(),
                depth: fr.depth + 1,
                ..Node::default()
            };
            if let Err(s) = ensure(fr, self.data.len(), n, probe) {
                return s;
            }
        }
        let new_depth = fr.depth + 1;
        let hard_end = size.map(|n| start + n);
        if new_depth > self.p.max_depth {
            let node = Node {
                name: field.name.clone(),
                kind: "struct".into(),
                start,
                end: start,
                status: "error".into(),
                note: Some(format!(
                    "递归深度超过上限 max_depth={}",
                    self.p.max_depth
                )),
                depth: new_depth,
                ..Node::default()
            };
            return Stop::Fail(
                format!(
                    "字段 {} 递归深度超过配置上限 {}",
                    field.name, self.p.max_depth
                ),
                start,
                self.child_path(fr, field),
                node,
            );
        }
        let mut child = Frame {
            pos: start,
            struct_start: start,
            scope: Scope::default(),
            children: Vec::new(),
            hard_end,
            depth: new_depth,
            path: {
                let mut p = fr.path.clone();
                p.push(field.name.clone());
                p
            },
        };
        let result = self.parse_struct(inner, &mut child);
        match result {
            Stop::Ok(end) => {
                if let Some(he) = hard_end {
                    if end != he {
                        let mut wrapped = Node {
                            name: field.name.clone(),
                            kind: "struct".into(),
                            start,
                            end,
                            status: "error".into(),
                            note: Some(format!(
                                "定界结构未占满声明区间（剩余 {} 字节）",
                                he - end
                            )),
                            children: child.children,
                            depth: new_depth,
                            ..Node::default()
                        };
                        self.propagate(&mut wrapped, "error");
                        fr.children.push(wrapped);
                        fr.pos = end;
                        return Stop::Fail(
                            format!("字段 {} 的定界区间未被完全消耗", field.name),
                            end,
                            self.child_path(fr, field),
                            Node::default(),
                        );
                    }
                }
                fr.pos = end;
                fr.children.push(Node {
                    name: field.name.clone(),
                    kind: "struct".into(),
                    start,
                    end,
                    status: "complete".into(),
                    children: child.children,
                    depth: new_depth,
                    ..Node::default()
                });
                Stop::Ok(end)
            }
            Stop::Need(n, _) => {
                let mut wrapped = Node {
                    name: field.name.clone(),
                    kind: "struct".into(),
                    start,
                    end: child.pos,
                    status: "incomplete".into(),
                    children: child.children,
                    depth: new_depth,
                    ..Node::default()
                };
                self.propagate(&mut wrapped, "incomplete");
                fr.children.push(wrapped);
                fr.pos = child.pos;
                Stop::Need(n, Node::default())
            }
            Stop::Fail(msg, off, _path, _node) => {
                let mut wrapped = Node {
                    name: field.name.clone(),
                    kind: "struct".into(),
                    start,
                    end: off,
                    status: "error".into(),
                    children: child.children,
                    depth: new_depth,
                    ..Node::default()
                };
                self.propagate(&mut wrapped, "error");
                fr.children.push(wrapped);
                fr.pos = off;
                Stop::Fail(msg, off, self.child_path(fr, field), Node::default())
            }
        }
    }
}

impl<'a> Engine<'a> {
    fn parse_repeat(
        &mut self,
        field: &Field,
        count_expr: &Expr,
        body: &RepeatBody,
        fr: &mut Frame,
    ) -> Stop {
        let start = fr.pos;
        let count = match eval_usize(count_expr, &fr.scope, start) {
            Ok(n) => n,
            Err(err) => {
                return Stop::Fail(
                    format!("repeat {} 计数表达式失败：{}", field.name, err.message),
                    start,
                    self.child_path(fr, field),
                    self.fail_node(fr, field, start, err.message),
                );
            }
        };

        // 恶意计数防护：单次零字节结构重复会导致不前进。
        let mut node = Node {
            name: field.name.clone(),
            kind: "repeat".into(),
            start,
            end: start,
            status: "complete".into(),
            depth: fr.depth + 1,
            ..Node::default()
        };
        let mut pos = start;
        for i in 0..count {
            let item_name = format!("[{}]", i);
            let before = pos;
            let mut item_frame = Frame {
                pos,
                struct_start: pos,
                scope: Scope::default(),
                children: Vec::new(),
                hard_end: fr.hard_end,
                depth: fr.depth + 2,
                path: {
                    let mut p = fr.path.clone();
                    p.push(field.name.clone());
                    p.push(item_name.clone());
                    p
                },
            };
            let result = match body {
                RepeatBody::Raw => {
                    let byte_field = Field {
                        name: "byte".into(),
                        kind: FieldKind::FixedBytes(1),
                        when: None,
                        line: 0,
                    };
                    let wrapper = StructDef {
                        name: None,
                        fields: vec![byte_field],
                    };
                    self.parse_field(&wrapper, &wrapper.fields[0], &mut item_frame)
                }
                RepeatBody::StructRef(name) => {
                    let inner = self.p.find(name).expect("compile 保证").clone();
                    self.parse_named_ref(
                        &Field {
                            name: item_name.clone(),
                            kind: FieldKind::StructRef(name.clone(), None),
                            when: None,
                            line: 0,
                        },
                        &inner,
                        None,
                        &mut item_frame,
                    )
                }
                RepeatBody::StructDef(inner) => self.parse_inline(
                    &Field {
                        name: item_name.clone(),
                        kind: FieldKind::InlineStruct(inner.clone()),
                        when: None,
                        line: 0,
                    },
                    inner,
                    None,
                    &mut item_frame,
                ),
            };
            match result {
                Stop::Ok(end) => {
                    let mut item = Node {
                        name: item_name,
                        kind: "item".into(),
                        start: before,
                        end,
                        status: "complete".into(),
                        children: item_frame.children,
                        depth: fr.depth + 2,
                        ..Node::default()
                    };
                    self.propagate(&mut item, "complete");
                    node.children.push(item);
                    pos = end;
                }
                Stop::Need(n, _) => {
                    node.end = pos;
                    node.status = "incomplete".into();
                    fr.children.push(node);
                    fr.pos = pos;
                    return Stop::Need(n, Node::default());
                }
                Stop::Fail(msg, off, _p, _n) => {
                    node.end = off;
                    node.status = "error".into();
                    fr.children.push(node);
                    fr.pos = off;
                    return Stop::Fail(
                        msg,
                        off,
                        {
                            let mut p = fr.path.clone();
                            p.push(field.name.clone());
                            p.push(item_name);
                            p
                        },
                        Node::default(),
                    );
                }
            }
        }
        node.end = pos;
        fr.pos = pos;
        fr.children.push(node);
        Stop::Ok(pos)
    }
}

impl<'a> Engine<'a> {
    fn parse_checksum(
        &mut self,
        def: &StructDef,
        field: &Field,
        spec: &CheckSpec,
        fr: &mut Frame,
    ) -> Stop {
        let width = match spec.algo {
            CheckAlgo::Sum8 | CheckAlgo::Xor8 => 1,
            CheckAlgo::Sum16Be => 2,
        };
        let start = fr.pos;
        let probe = Node::leaf_probe(field, start, fr.depth);
        if let Err(s) = ensure(fr, self.data.len(), width, probe) {
            return s;
        }
        let end = start + width;
        let stored = int_value(self.data, IntKind::U8, start) as u64;
        let stored = match spec.algo {
            CheckAlgo::Sum8 | CheckAlgo::Xor8 => stored,
            CheckAlgo::Sum16Be => int_value(self.data, IntKind::U16Be, start),
        };

        // 区间允许以校验字段自身（@cs / @cs.end）为边界，预登记其占位。
        fr.scope.fields.push((
            field.name.clone(),
            crate::eval::ResolvedField {
                value: stored,
                start,
                end,
            },
        ));

        let default_to = RangeBound::StartOf(field.name.clone());
        let default_from = RangeBound::StructStart;
        let from_b = spec.from.clone().unwrap_or(default_from);
        let to_b = spec.to.clone().unwrap_or(default_to);
        let struct_end = fr.hard_end;
        let from = match resolve_bound(&from_b, &fr.scope, fr.struct_start, struct_end)
        {
            Ok(v) => v,
            Err(e) => {
                return Stop::Fail(
                    format!("校验和 {} 区间起点无法解析：{}", field.name, e.message),
                    start,
                    self.child_path(fr, field),
                    self.fail_node(fr, field, start, e.message),
                );
            }
        };
        let to = match resolve_bound(&to_b, &fr.scope, fr.struct_start, struct_end) {
            Ok(v) => v,
            Err(e) => {
                return Stop::Fail(
                    format!("校验和 {} 区间终点无法解析：{}", field.name, e.message),
                    start,
                    self.child_path(fr, field),
                    self.fail_node(fr, field, start, e.message),
                );
            }
        };

        let mut computed: u64 = 0;
        let mut valid_range = true;
        let mut range_note = String::new();
        if from > to {
            valid_range = false;
            range_note = format!("校验区间起点 {} 大于终点 {}", from, to);
        }
        let cap = match fr.hard_end {
            Some(h) => h.min(self.data.len()),
            None => self.data.len(),
        };
        let clamped_to = to.min(cap);
        if to > cap {
            valid_range = false;
            range_note = format!("校验区间终点 {} 超出父结构边界 {}", to, cap);
        }
        if from <= clamped_to {
            let slice = &self.data[from..clamped_to];
            computed = match spec.algo {
                CheckAlgo::Sum8 => slice.iter().map(|b| *b as u64).sum::<u64>() & 0xff,
                CheckAlgo::Xor8 => slice.iter().fold(0u8, |a, b| a ^ b) as u64,
                CheckAlgo::Sum16Be => {
                    slice.chunks(2).fold(0u64, |acc, ch| {
                        let wv = if ch.len() == 2 {
                            u16::from_be_bytes([ch[0], ch[1]]) as u64
                        } else {
                            ch[0] as u64
                        };
                        acc.wrapping_add(wv)
                    }) & 0xffff
                }
            };
            if spec.skip_self
                && start >= from
                && start < clamped_to
                && end <= clamped_to
            {
                let self_bytes = match spec.algo {
                    CheckAlgo::Sum8 | CheckAlgo::Xor8 => {
                        slice[start - from..end - from]
                            .iter()
                            .map(|b| *b as u64)
                            .sum::<u64>()
                            & 0xff
                    }
                    CheckAlgo::Sum16Be => {
                        if end - start == 2 && start + 2 <= clamped_to {
                            u16::from_be_bytes([
                                slice[start - from],
                                slice[start - from + 1],
                            ]) as u64
                        } else {
                            0
                        }
                    }
                };
                computed = computed.wrapping_sub(self_bytes)
                    & match spec.algo {
                        CheckAlgo::Sum8 | CheckAlgo::Xor8 => 0xff,
                        CheckAlgo::Sum16Be => 0xffff,
                    };
            }
        }

        let algo_name = match spec.algo {
            CheckAlgo::Sum8 => "sum8",
            CheckAlgo::Xor8 => "xor8",
            CheckAlgo::Sum16Be => "sum16be",
        };
        let mismatch = stored != computed;
        let note = if mismatch {
            Some(format!(
                "{} 校验不匹配：存储 0x{:0width$x}，计算 0x{:0width$x}，覆盖 [{},{})",
                algo_name,
                stored,
                computed,
                from,
                to,
                width = width * 2
            ))
        } else {
            Some(format!(
                "{} 校验通过：0x{:0width$x}，覆盖 [{},{})",
                algo_name,
                stored,
                from,
                to,
                width = width * 2
            ))
        };

        if !valid_range {
            self.warnings.push(Diag {
                kind: "checksum_range".into(),
                path: self.child_path(fr, field),
                offset: start,
                message: range_note,
                need: None,
            });
        }
        if mismatch {
            self.warnings.push(Diag {
                kind: "checksum_mismatch".into(),
                path: self.child_path(fr, field),
                offset: start,
                message: note.clone().unwrap_or_default(),
                need: None,
            });
        }

        fr.pos = end;
        fr.children.push(Node {
            name: field.name.clone(),
            kind: "checksum".into(),
            start,
            end,
            value: Some(format!("0x{:0width$x}", stored, width = width * 2)),
            numeric: Some(stored),
            status: "complete".into(),
            note,
            depth: fr.depth + 1,
            ..Node::default()
        });
        let _ = def;
        Stop::Ok(end)
    }
}

pub fn node_json(n: &Node) -> Json {
    let mut o = Json::obj();
    o.put("name", Json::str(&n.name));
    o.put("kind", Json::str(&n.kind));
    o.put("start", Json::Int(n.start as i64));
    o.put("end", Json::Int(n.end as i64));
    if let Some(v) = &n.value {
        o.put("value", Json::str(v));
    }
    if let Some(v) = n.numeric {
        o.put("numeric", Json::Int(v as i64));
    }
    o.put("status", Json::str(&n.status));
    if let Some(note) = &n.note {
        o.put("note", Json::str(note));
    }
    let children: Vec<Json> = n.children.iter().map(node_json).collect();
    o.put("children", Json::Arr(children));
    o
}

pub fn diag_json(d: &Diag) -> Json {
    let mut o = Json::obj();
    o.put("kind", Json::str(&d.kind));
    o.put(
        "path",
        Json::Arr(d.path.iter().map(|s| Json::str(s)).collect()),
    );
    o.put("offset", Json::Int(d.offset as i64));
    o.put("message", Json::str(&d.message));
    if let Some(n) = d.need {
        o.put("need", Json::Int(n as i64));
    }
    o
}

impl ParseOut {
    pub fn to_json(&self) -> Json {
        let mut o = Json::obj();
        o.put("status", Json::str(&self.status));
        o.put("tree", node_json(&self.tree));
        if let Some(d) = &self.diag {
            o.put("diag", diag_json(d));
        }
        o.put(
            "warnings",
            Json::Arr(self.warnings.iter().map(diag_json).collect()),
        );
        o
    }

    /// 解析树的确定性摘要：只含结构信息（名称/区间/数值/状态），不含说明文字。
    pub fn tree_summary(&self) -> String {
        let canon = tree_canonical(&self.tree);
        crate::sha256::hex(canon.as_bytes())
    }
}

fn tree_canonical(n: &Node) -> String {
    let mut j = Json::obj();
    j.put("name", Json::str(&n.name));
    j.put("kind", Json::str(&n.kind));
    j.put("start", Json::Int(n.start as i64));
    j.put("end", Json::Int(n.end as i64));
    if let Some(v) = n.numeric {
        j.put("numeric", Json::Int(v as i64));
    }
    j.put("status", Json::str(&n.status));
    j.put(
        "children",
        Json::Arr(n.children.iter().map(|c| Json::str(&tree_canonical(c))).collect()),
    );
    j.canonical()
}

/// 收集所有节点的字节覆盖区间，便于前端反查。
pub fn collect_ranges(n: &Node, out: &mut Vec<(String, usize, usize)>) {
    if !n.children.is_empty() {
        out.push((n.name.clone(), n.start, n.end));
    } else {
        out.push((n.name.clone(), n.start, n.end));
    }
    for c in &n.children {
        collect_ranges(c, out);
    }
}

/// 从部分树中取最深路径（优先错误/不完整分支）。
pub fn deepest_path(nodes: &[Node]) -> Vec<String> {
    fn walk(n: &Node, acc: &mut Vec<String>, depth: usize, best: &mut (usize, Vec<String>)) {
        acc.push(n.name.clone());
        let interesting = n.status == "error" || n.status == "incomplete";
        if interesting && depth > best.0 {
            *best = (depth, acc.clone());
        }
        for c in &n.children {
            walk(c, acc, depth + 1, best);
        }
        acc.pop();
    }
    let mut best = (0usize, Vec::new());
    for n in nodes {
        walk(n, &mut Vec::new(), 0, &mut best);
    }
    best.1
}
