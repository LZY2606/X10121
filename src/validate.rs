//! 协议描述校验：保存版本前保证结构、引用与宽度合法。

use crate::model::*;
use std::collections::HashSet;

/// 校验一份协议，返回所有错误；空向量表示通过。
pub fn validate(spec: &ProtocolSpec) -> Vec<String> {
    let mut errs = Vec::new();
    if spec.name.trim().is_empty() {
        errs.push("协议名称不能为空".into());
    }
    if !spec.structs.contains_key(&spec.root) {
        errs.push(format!("根结构体 `{}` 不存在", spec.root));
    }
    for (sname, sdef) in &spec.structs {
        validate_struct(spec, sname, sdef, &mut errs);
    }
    errs
}

fn validate_struct(spec: &ProtocolSpec, sname: &str, sdef: &StructDef, errs: &mut Vec<String>) {
    let mut seen: HashSet<String> = HashSet::new();
    for f in &sdef.fields {
        validate_field(spec, sname, f, &mut seen, errs);
    }
}

fn validate_field(
    spec: &ProtocolSpec,
    sname: &str,
    f: &FieldDef,
    prior: &mut HashSet<String>,
    errs: &mut Vec<String>,
) {
    let path = || format!("{}.{}", sname, f.name());
    if prior.contains(f.name()) {
        errs.push(format!("结构体 `{}` 中字段名 `{}` 重复", sname, f.name()));
    }
    prior.insert(f.name().to_string());

    match f {
        FieldDef::Int { width, .. } => {
            if !(1..=8).contains(width) {
                errs.push(format!("{}: 整数宽度必须在 1..=8", path()));
            }
        }
        FieldDef::Bytes { length, .. } => check_expr(length, prior, &path(), errs),
        FieldDef::Payload { length_field, .. } => {
            if !prior.contains(length_field) {
                errs.push(format!(
                    "{}: payload 长度字段 `{}` 必须是前置字段",
                    path(),
                    length_field
                ));
            }
        }
        FieldDef::Struct { ty, length, .. } => {
            if !spec.structs.contains_key(ty) {
                errs.push(format!("{}: 引用的结构体 `{}` 不存在", path(), ty));
            }
            if let Some(len) = length {
                check_expr(len, prior, &path(), errs);
            }
        }
        FieldDef::Vector {
            count,
            bounded,
            element,
            ..
        } => {
            if count.is_none() && bounded.is_none() {
                errs.push(format!("{}: vector 必须给出 count 或 bounded", path()));
            }
            if let Some(c) = count {
                check_expr(c, prior, &path(), errs);
            }
            if let Some(b) = bounded {
                check_expr(b, prior, &path(), errs);
            }
            match element.as_ref() {
                FieldDef::Vector { .. } => {
                    errs.push(format!("{}: vector 元素不能直接是 vector", path()))
                }
                FieldDef::Switch { .. } => {
                    errs.push(format!("{}: vector 元素不能直接是 switch", path()))
                }
                other => {
                    let mut child_prior = HashSet::new();
                    validate_field(spec, sname, other, &mut child_prior, errs);
                }
            }
        }
        FieldDef::Switch {
            on,
            cases,
            fallback,
            ..
        } => {
            if !prior.contains(on) {
                errs.push(format!("{}: switch 判据字段 `{}` 必须是前置字段", path(), on));
            }
            if cases.is_empty() && fallback.is_none() {
                errs.push(format!("{}: switch 至少需要一个分支或 fallback", path()));
            }
            for (key, case) in cases {
                if key.parse::<i128>().is_err() {
                    errs.push(format!("{}: 分支键 `{}` 必须是整数", path(), key));
                }
                let mut sub: HashSet<String> = prior.iter().cloned().collect();
                for cf in &case.fields {
                    validate_field(spec, sname, cf, &mut sub, errs);
                }
            }
            if let Some(fb) = fallback {
                let mut sub: HashSet<String> = prior.iter().cloned().collect();
                for cf in &fb.fields {
                    validate_field(spec, sname, cf, &mut sub, errs);
                }
            }
        }
        FieldDef::Checksum {
            width,
            algorithm,
            end,
            ..
        } => {
            if *width != algorithm.required_width() {
                errs.push(format!(
                    "{}: 算法 {:?} 需要 {} 字节宽度",
                    path(),
                    algorithm,
                    algorithm.required_width()
                ));
            }
            if let Some(e) = end {
                match e {
                    EndRef::StructEnd => {}
                    EndRef::Field(name) => {
                        if !prior.contains(name) {
                            errs.push(format!("{}: 覆盖终点字段 `{}` 必须前置", path(), name));
                        }
                    }
                }
            }
        }
    }
}

fn check_expr(expr: &LengthExpr, prior: &HashSet<String>, path: &str, errs: &mut Vec<String>) {
    if let LengthExpr::Field(name) = expr {
        if !prior.contains(name) {
            errs.push(format!("{}: 引用的长度字段 `{}` 必须是前置字段", path, name));
        }
    }
}
