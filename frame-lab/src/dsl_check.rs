//! DSL 语义检查与规范化。

use crate::model::*;

/// 收集表达式里引用的普通字段名（不含 @偏移标记）。
pub fn referenced_vars(e: &Expr, out: &mut Vec<String>) {
    match e {
        Expr::Lit(_) => {}
        Expr::Var(n) => out.push(n.clone()),
        Expr::EndOf(n) | Expr::StartOf(n) => {
            let _ = n;
        }
        Expr::Bin(a, _, b) => {
            referenced_vars(a, out);
            referenced_vars(b, out);
        }
    }
}

fn range_refs(b: &RangeBound) -> Option<&str> {
    match b {
        RangeBound::StartOf(n) | RangeBound::EndOf(n) => Some(n),
        RangeBound::StructStart | RangeBound::StructEnd | RangeBound::Const(_) => None,
    }
}

pub fn validate(mut p: Protocol) -> Result<Protocol, String> {
    // 结构名唯一
    let mut seen = std::collections::HashSet::new();
    for s in &p.structs {
        let name = s
            .name
            .as_ref()
            .ok_or_else(|| "内部错误：命名结构缺失名称".to_string())?;
        if !seen.insert(name.clone()) {
            return Err(format!("结构 {} 重复定义", name));
        }
    }
    if p.find(&p.root).is_none() {
        return Err(format!("root 指向未定义的结构 {}", p.root));
    }
    if p.max_depth == 0 {
        return Err("max_depth 必须 >= 1".to_string());
    }

    for s in &p.structs {
        let sname = s.name.as_deref().unwrap_or("<匿名>");
        let mut names = std::collections::HashSet::new();
        let mut assert_count = 0;

        for (idx, f) in s.fields.iter().enumerate() {
            // assert 自动命名
            let normalized_name = if matches!(f.kind, FieldKind::Assert(_)) {
                assert_count += 1;
                if f.name == "assert" {
                    format!("assert_{}", assert_count)
                } else {
                    f.name.clone()
                }
            } else {
                f.name.clone()
            };
            let _ = normalized_name;

            if !names.insert(f.name.clone()) && !matches!(f.kind, FieldKind::Assert(_)) {
                return Err(format!("结构 {} 中字段 {} 重名", sname, f.name));
            }

            // 普通 Var 引用必须指向此前声明的整数字段
            let mut vars = Vec::new();
            match &f.kind {
                FieldKind::Int(_) | FieldKind::FixedBytes(_) => {}
                FieldKind::VarBytes(e) => referenced_vars(e, &mut vars),
                FieldKind::InlineStruct(inner) => check_inline(sname, f, inner)?,
                FieldKind::StructRef(target, size) => {
                    if p.find(target).is_none() {
                        return Err(format!(
                            "{}:{}（第 {} 行）引用了未定义结构 {}",
                            sname, f.name, f.line, target
                        ));
                    }
                    if let Some(e) = size {
                        referenced_vars(e, &mut vars);
                    }
                }
                FieldKind::Repeat(count, body) => {
                    referenced_vars(count, &mut vars);
                    if let RepeatBody::StructRef(target) = body {
                        if p.find(target).is_none() {
                            return Err(format!(
                                "{}:{}（第 {} 行）repeat 引用了未定义结构 {}",
                                sname, f.name, f.line, target
                            ));
                        }
                    }
                    if let RepeatBody::StructDef(inner) = body {
                        check_inline(sname, f, inner)?;
                    }
                }
                FieldKind::Checksum(spec) => {
                    if idx + 1 != s.fields.len() {
                        return Err(format!(
                            "结构 {} 的校验和字段 {} 必须是最后一个字段",
                            sname, f.name
                        ));
                    }
                    for b in [&spec.from, &spec.to].into_iter().flatten() {
                        if let Some(n) = range_refs(b) {
                            if s.fields.iter().all(|x| x.name != n) {
                                return Err(format!(
                                    "结构 {} 的校验和 {} 引用了不存在的字段 {}",
                                    sname, f.name, n
                                ));
                            }
                        }
                    }
                }
                FieldKind::Assert(e) => referenced_vars(e, &mut vars),
            }
            if let Some(w) = &f.when {
                referenced_vars(w, &mut vars);
            }
            for v in &vars {
                let prev = s.fields[..idx].iter().any(|x| x.name == *v && x.is_int());
                if !prev {
                    return Err(format!(
                        "结构 {} 的字段 {}（第 {} 行）引用了此前未声明的整数字段 {}",
                        sname, f.name, f.line, v
                    ));
                }
            }

            // rest 字段只能最后出现
            if is_rest(&f.kind) && idx + 1 != s.fields.len() {
                return Err(format!(
                    "结构 {} 的字段 {} 消耗剩余字节，必须放在最后",
                    sname, f.name
                ));
            }
        }
    }

    // 将 assert 字段名规范化（原地）
    for s in &mut p.structs {
        let mut n = 0;
        for f in &mut s.fields {
            if matches!(f.kind, FieldKind::Assert(_)) {
                n += 1;
                if f.name == "assert" {
                    f.name = format!("assert_{}", n);
                }
            }
        }
    }

    Ok(p)
}

fn check_inline(sname: &str, owner: &Field, inner: &StructDef) -> Result<(), String> {
    for f in &inner.fields {
        match &f.kind {
            FieldKind::StructRef(target, size) => {
                if size.is_none() && !is_last(inner, f) {
                    return Err(format!(
                        "结构 {} 的字段 {} 内联结构含非末尾的剩余字节引用 {}",
                        sname, owner.name, target
                    ));
                }
            }
            FieldKind::Repeat(_, body) => {
                if let RepeatBody::StructDef(deep) = body {
                    check_inline(sname, owner, deep)?;
                }
            }
            FieldKind::InlineStruct(deep) => check_inline(sname, owner, deep)?,
            _ => {}
        }
    }
    Ok(())
}

fn is_last(s: &StructDef, f: &Field) -> bool {
    s.fields.last().map(|x| std::ptr::eq(x, f)).unwrap_or(false)
}

/// 解析 + 语义检查的入口。
pub fn compile(src: &str) -> Result<Protocol, String> {
    let p = crate::dsl_parse::build_protocol(src)?;
    validate(p)
}
