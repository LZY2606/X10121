// 解析树 -> API JSON，以及用于导入导出一致性的确定性摘要。

use crate::hash::{hex, sha256};
use crate::json::{self, Value};
use crate::parser::{Node, NodeStatus, ParseResult};

fn status_value(s: NodeStatus) -> Value {
    Value::Str(s.as_str().to_string())
}

pub fn node_to_value(n: &Node) -> Value {
    let children: Vec<Value> = n.children.iter().map(node_to_value).collect();
    let path: Vec<Value> = n.path.iter().map(|s| Value::Str(s.clone())).collect();
    let diags: Vec<Value> = n
        .diagnostics
        .iter()
        .map(|s| Value::Str(s.clone()))
        .collect();
    Value::Obj(vec![
        ("path".to_string(), Value::Arr(path)),
        ("name".to_string(), Value::Str(n.name.clone())),
        ("kind".to_string(), Value::Str(n.kind.clone())),
        ("start".to_string(), Value::Int(n.start as i128)),
        ("end".to_string(), Value::Int(n.end as i128)),
        ("status".to_string(), status_value(n.status)),
        ("value".to_string(), n.value.clone().unwrap_or(Value::Null)),
        ("display".to_string(), Value::Str(n.display.clone())),
        ("diagnostics".to_string(), Value::Arr(diags)),
        ("children".to_string(), Value::Arr(children)),
    ])
}

/// 只保留结构摘要：路径/区间/状态/值/诊断（不包含易变的 display 空格风格）。
fn node_digest_value(n: &Node) -> Value {
    Value::Obj(vec![
        (
            "path".to_string(),
            Value::Arr(n.path.iter().map(|s| Value::Str(s.clone())).collect()),
        ),
        ("start".to_string(), Value::Int(n.start as i128)),
        ("end".to_string(), Value::Int(n.end as i128)),
        ("status".to_string(), status_value(n.status)),
        ("value".to_string(), n.value.clone().unwrap_or(Value::Null)),
        (
            "diagnostics".to_string(),
            Value::Arr(n.diagnostics.iter().map(|s| Value::Str(s.clone())).collect()),
        ),
        (
            "children".to_string(),
            Value::Arr(n.children.iter().map(node_digest_value).collect()),
        ),
    ])
}

pub fn tree_digest(tree: Option<&Node>) -> String {
    match tree {
        Some(t) => {
            let canon = json::canonicalize(&node_digest_value(t));
            hex(&sha256(json::stringify(&canon).as_bytes()))
        }
        None => hex(&sha256(b"no-tree")),
    }
}

pub fn result_to_value(r: &ParseResult) -> Value {
    let mut out = vec![
        ("status".to_string(), status_value(r.status)),
        ("consumed".to_string(), Value::Int(r.consumed as i128)),
        ("input_len".to_string(), Value::Int(r.input_len as i128)),
        (
            "warnings".to_string(),
            Value::Arr(r.warnings.iter().map(|s| Value::Str(s.clone())).collect()),
        ),
        ("tree_digest".to_string(), Value::Str(r.digest.clone())),
    ];
    if let Some(t) = &r.tree {
        out.push(("tree".to_string(), node_to_value(t)));
    } else {
        out.push(("tree".to_string(), Value::Null));
    }
    if let Some(e) = &r.error {
        let mut eo = vec![
            ("kind".to_string(), Value::Str(match e.kind {
                crate::parser::FailKind::Incomplete => "incomplete",
                crate::parser::FailKind::Violation => "violation",
            }.to_string())),
            ("message".to_string(), Value::Str(e.message.clone())),
            (
                "path".to_string(),
                Value::Arr(e.path.iter().map(|s| Value::Str(s.clone())).collect()),
            ),
            ("offset".to_string(), Value::Int(e.offset as i128)),
        ];
        if let Some(n) = e.need_total {
            eo.push(("need_total".to_string(), Value::Int(n as i128)));
            let still_need = n.saturating_sub(r.input_len);
            eo.push(("still_need".to_string(), Value::Int(still_need as i128)));
        }
        out.push(("error".to_string(), Value::Obj(eo)));
    } else {
        out.push(("error".to_string(), Value::Null));
    }
    Value::Obj(out)
}
