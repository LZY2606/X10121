//! 帧编码器：按 JSON 提供的字段值生成合法帧。
//!
//! - 长度字段：当后续 payload 的长度表达式直接引用该字段时，自动回填实际大小。
//! - 校验和：按声明自动计算，默认跳过自身字段。
//! - 条件：与解析器共用同一表达式。

use crate::eval::{eval_bool, resolve_bound, Scope};
use crate::json::Json;
use crate::model::*;

#[derive(Debug)]
pub struct EncodeError {
    pub path: Vec<String>,
    pub message: String,
}

impl EncodeError {
    fn at(path: Vec<String>, message: impl Into<String>) -> Self {
        EncodeError {
            path,
            message: message.into(),
        }
    }
}

#[derive(Clone)]
struct LenPatch {
    /// 该长度字段引用关系：payload 的长度表达式是否为单个此字段引用
    length_field: String,
    at: std::ops::Range<usize>,
    kind: IntKind,
    value_for: LengthTarget,
}

#[derive(Clone)]
enum LengthTarget {
    /// payload 字节数
    PayloadSize(u64),
    /// repeat 的实际计数
    RepeatCount(u64),
}

struct CheckPatch {
    at: std::ops::Range<usize>,
    width: usize,
    algo: CheckAlgo,
    from: Option<RangeBound>,
    to: Option<RangeBound>,
    skip_self: bool,
    struct_start: usize,
    scope: Scope,
    struct_end: usize,
}

pub fn encode(p: &Protocol, values: &Json) -> Result<Vec<u8>, EncodeError> {
    let root = p.find(&p.root).expect("compile 保证");
    let mut enc = Enc { p };
    let mut buf = Vec::new();
    let mut scope = Scope::default();
    enc.struct_values(
        root,
        values,
        &mut buf,
        &mut scope,
        &[p.root.clone()],
        None,
    )?;
    Ok(buf)
}

fn write_int(buf: &mut Vec<u8>, kind: IntKind, val: u64) {
    match kind {
        IntKind::U8 => buf.push((val & 0xff) as u8),
        IntKind::U16Be => buf.extend_from_slice(&(val as u16).to_be_bytes()),
        IntKind::U16Le => buf.extend_from_slice(&(val as u16).to_le_bytes()),
        IntKind::U24Be => {
            buf.push(((val >> 16) & 0xff) as u8);
            buf.push(((val >> 8) & 0xff) as u8);
            buf.push((val & 0xff) as u8);
        }
        IntKind::U32Be => buf.extend_from_slice(&(val as u32).to_be_bytes()),
        IntKind::U32Le => buf.extend_from_slice(&(val as u32).to_le_bytes()),
    }
}

fn write_int_at(buf: &mut [u8], kind: IntKind, val: u64) {
    let bytes = match kind {
        IntKind::U8 => vec![(val & 0xff) as u8],
        IntKind::U16Be => (val as u16).to_be_bytes().to_vec(),
        IntKind::U16Le => (val as u16).to_le_bytes().to_vec(),
        IntKind::U24Be => {
            vec![((val >> 16) & 0xff) as u8, ((val >> 8) & 0xff) as u8, (val & 0xff) as u8]
        }
        IntKind::U32Be => (val as u32).to_be_bytes().to_vec(),
        IntKind::U32Le => (val as u32).to_le_bytes().to_vec(),
    };
    buf[..bytes.len()].copy_from_slice(&bytes);
}

fn json_u64(v: Option<&Json>, what: &str, path: &[String]) -> Result<u64, EncodeError> {
    match v {
        Some(Json::Int(n)) if *n >= 0 => Ok(*n as u64),
        _ => Err(EncodeError::at(path.to_vec(), format!("{} 需要非负整数", what))),
    }
}

fn json_hex(v: Option<&Json>, what: &str, path: &[String]) -> Result<Vec<u8>, EncodeError> {
    let s = match v {
        Some(Json::Str(s)) => s,
        _ => return Err(EncodeError::at(path.to_vec(), format!("{} 需要十六进制字符串", what))),
    };
    crate::hex::decode(s).map_err(|e| EncodeError::at(path.to_vec(), e))
}

struct Enc<'a> {
    p: &'a Protocol,
}

impl<'a> Enc<'a> {
    fn struct_values(
        &mut self,
        def: &StructDef,
        values: &Json,
        buf: &mut Vec<u8>,
        scope: &mut Scope,
        path: &[String],
        hard_size: Option<usize>,
    ) -> Result<usize, EncodeError> {
        let struct_start = buf.len();
        let mut len_patches: Vec<LenPatch> = Vec::new();
        let mut check_patches: Vec<CheckPatch> = Vec::new();
        let mut placeholders: std::collections::HashSet<String> = std::collections::HashSet::new();

        for field in &def.fields {
            if let Some(w) = &field.when {
                let active = eval_bool(w, scope, buf.len())
                    .map_err(|e| EncodeError::at(self.fpath(path, field), e.message))?;
                if !active {
                    continue;
                }
            }
            self.encode_field(
                def,
                field,
                values,
                buf,
                scope,
                path,
                &mut len_patches,
                &mut check_patches,
                struct_start,
                &mut placeholders,
            )?;
        }

        let struct_end = buf.len();
        if let Some(required) = hard_size {
            if struct_end - struct_start != required {
                return Err(EncodeError::at(
                    path.to_vec(),
                    format!(
                        "定界结构实际大小 {} 与声明大小 {} 不一致",
                        struct_end - struct_start,
                        required
                    ),
                ));
            }
        }

        // 回填长度字段：RegionEnd 表示 payload 结束绝对偏移
        for patch in &len_patches {
            let val = match patch.value_for {
                LengthTarget::PayloadSize(n) => n,
                LengthTarget::RepeatCount(n) => n,
            };
            write_int_at(&mut buf[patch.at.clone()], patch.kind, val);
        }

        // 绑定本结构内新增校验补丁的结构结束位置
        for cp in check_patches.iter_mut() {
            if cp.struct_end == 0 {
                cp.struct_end = struct_end;
            }
        }

        // 计算校验和（此时长度字段已回填，区间完整）
        for cp in &check_patches {
            let end_bound = cp.struct_end;
            let from = match &cp.from {
                None => cp.struct_start,
                Some(b) => resolve_bound(b, &cp.scope, cp.struct_start, Some(end_bound))
                    .map_err(|e| EncodeError::at(path.to_vec(), e.message))?,
            };
            let to = match &cp.to {
                None => end_bound,
                Some(b) => resolve_bound(b, &cp.scope, cp.struct_start, Some(end_bound))
                    .map_err(|e| EncodeError::at(path.to_vec(), e.message))?,
            };
            if from > to || to > buf.len() {
                return Err(EncodeError::at(
                    path.to_vec(),
                    format!("校验和区间 [{},{}) 非法（缓冲区 {} 字节）", from, to, buf.len()),
                ));
            }
            let mut slice: Vec<u8> = buf[from..to].to_vec();
            if cp.skip_self {
                let s = cp.at.start.saturating_sub(from);
                let e = cp.at.end.saturating_sub(from).min(slice.len());
                if s < e {
                    for b in &mut slice[s..e] {
                        *b = 0;
                    }
                }
            }
            let val = match cp.algo {
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
            let out = &mut buf[cp.at.clone()];
            match cp.algo {
                CheckAlgo::Sum8 | CheckAlgo::Xor8 => out[0] = val as u8,
                CheckAlgo::Sum16Be => {
                    let b = (val as u16).to_be_bytes();
                    out[0] = b[0];
                    out[1] = b[1];
                }
            }
        }

        Ok(struct_end - struct_start)
    }

    fn fpath(&self, path: &[String], field: &Field) -> Vec<String> {
        let mut p = path.to_vec();
        p.push(field.name.clone());
        p
    }
}

impl<'a> Enc<'a> {
    #[allow(clippy::too_many_arguments)]
    fn encode_field(
        &mut self,
        _def: &StructDef,
        field: &Field,
        values: &Json,
        buf: &mut Vec<u8>,
        scope: &mut Scope,
        path: &[String],
        len_patches: &mut Vec<LenPatch>,
        check_patches: &mut Vec<CheckPatch>,
        struct_start: usize,
        placeholders: &mut std::collections::HashSet<String>,
    ) -> Result<(), EncodeError> {
        let fpath = self.fpath(path, field);
        match &field.kind {
            FieldKind::Int(kind) => {
                let provided = values.get(&field.name);
                let start = buf.len();
                let idx = _def
                    .fields
                    .iter()
                    .position(|f| f.name == field.name)
                    .unwrap_or(0);
                let auto_candidate = provided.is_none()
                    && _def.fields.iter().skip(idx + 1).any(|later| {
                        later_uses(later, &field.name)
                    });
                match provided {
                    Some(v) => {
                        let n = json_u64(Some(v), &field.name, &fpath)?;
                        write_int(buf, *kind, n);
                    }
                    None if auto_candidate => {
                        write_int(buf, *kind, 0);
                        placeholders.insert(field.name.clone());
                        len_patches.push(LenPatch {
                            length_field: field.name.clone(),
                            at: start..start + kind.width(),
                            kind: *kind,
                            value_for: LengthTarget::PayloadSize(0),
                        });
                    }
                    None => {
                        write_int(buf, *kind, 0);
                    }
                }
                let end = buf.len();
                let val = read_buf_int(buf, *kind, start);
                scope.fields.push((
                    field.name.clone(),
                    crate::eval::ResolvedField {
                        value: val,
                        start,
                        end,
                    },
                ));
            }
            FieldKind::FixedBytes(n) => {
                let bytes = json_hex(values.get(&field.name), &field.name, &fpath)?;
                if bytes.len() != *n {
                    return Err(EncodeError::at(
                        fpath,
                        format!("字段 {} 需要 {} 字节，实际 {}", field.name, n, bytes.len()),
                    ));
                }
                buf.extend_from_slice(&bytes);
            }
            FieldKind::VarBytes(e) => {
                let linked = single_var(e);
                let bytes = json_hex(values.get(&field.name), &field.name, &fpath)?;
                let expected = eval_size(e, scope, &fpath)?;
                let is_placeholder = linked
                    .as_ref()
                    .map(|n| placeholders.contains(n))
                    .unwrap_or(false);
                match linked {
                    Some(len_name) if expected.is_none() || is_placeholder => {
                        buf.extend_from_slice(&bytes);
                        self.fill_len_patch(len_patches, &len_name, bytes.len() as u64);
                    }
                    _ => {
                        if let Some(exp) = expected {
                            if exp != bytes.len() {
                                return Err(EncodeError::at(
                                    fpath,
                                    format!(
                                        "字段 {} 声明长度 {} 与实际字节 {}",
                                        field.name,
                                        exp,
                                        bytes.len()
                                    ),
                                ));
                            }
                        }
                        buf.extend_from_slice(&bytes);
                    }
                }
            }
            FieldKind::Assert(e) => {
                match crate::eval::eval(e, scope, buf.len()) {
                    Ok(crate::eval::Val::Bool(true)) => {}
                    Ok(crate::eval::Val::Bool(false)) => {
                        return Err(EncodeError::at(fpath, format!("断言 {} 不成立", field.name)))
                    }
                    _ => return Err(EncodeError::at(fpath, "断言无法求值为布尔值")),
                }
            }
            FieldKind::Checksum(spec) => {
                let width = match spec.algo {
                    CheckAlgo::Sum8 | CheckAlgo::Xor8 => 1,
                    CheckAlgo::Sum16Be => 2,
                };
                let start = buf.len();
                // 允许提供校验值但随后会被重算覆盖（始终以计算为准）
                let _ = json_u64(values.get(&field.name).or(None), &field.name, &fpath).ok();
                for _ in 0..width {
                    buf.push(0);
                }
                let end = buf.len();
                scope.fields.push((
                    field.name.clone(),
                    crate::eval::ResolvedField {
                        value: 0,
                        start,
                        end,
                    },
                ));
                check_patches.push(CheckPatch {
                    at: start..end,
                    width,
                    algo: spec.algo,
                    from: spec.from.clone(),
                    to: spec.to.clone(),
                    skip_self: spec.skip_self,
                    struct_start,
                    scope: scope.clone(),
                    struct_end: 0,
                });
                // 结构结束位置在全部字段写完后统一回填
                let last = check_patches.len() - 1;
                let _ = last;
            }
            FieldKind::StructRef(name, size_expr) => {
                self.encode_struct_ref(
                    field,
                    name,
                    size_expr.as_ref(),
                    values.get(&field.name),
                    buf,
                    path,
                    len_patches,
                    struct_start,
                )?;
            }
            FieldKind::InlineStruct(inner) => {
                self.encode_inline_struct(
                    field,
                    inner,
                    None,
                    values.get(&field.name),
                    buf,
                    path,
                )?;
            }
            FieldKind::Repeat(count_expr, body) => {
                self.encode_repeat(
                    field,
                    count_expr,
                    body,
                    values.get(&field.name),
                    buf,
                    scope,
                    path,
                    len_patches,
                    struct_start,
                )?;
            }
        }
        Ok(())
    }

    fn fill_len_patch(&self, len_patches: &mut Vec<LenPatch>, len_name: &str, size: u64) {
        if let Some(p) = len_patches
            .iter_mut()
            .find(|p| p.length_field == len_name)
        {
            p.value_for = LengthTarget::PayloadSize(size);
        }
    }
}

fn int_kind_by_width(width: usize) -> Option<IntKind> {
    Some(match width {
        1 => IntKind::U8,
        2 => IntKind::U16Be,
        3 => IntKind::U24Be,
        4 => IntKind::U32Be,
        _ => return None,
    })
}

fn single_var(e: &Expr) -> Option<String> {
    match e {
        Expr::Var(n) => Some(n.clone()),
        _ => None,
    }
}

fn eval_size(e: &Expr, scope: &Scope, fpath: &[String]) -> Result<Option<usize>, EncodeError> {
    match crate::eval::eval(e, scope, 0) {
        Ok(crate::eval::Val::Int(n)) => Ok(Some(n as usize)),
        Ok(crate::eval::Val::Bool(_)) => Err(EncodeError::at(
            fpath.to_vec(),
            "长度表达式应为整数".to_string(),
        )),
        Err(err) => {
            // 引用字段缺失：允许自动回填
            if err.message.contains("尚未解析") || err.message.contains("不存在") {
                Ok(None)
            } else {
                Err(EncodeError::at(fpath.to_vec(), err.message))
            }
        }
    }
}

fn read_buf_int(buf: &[u8], kind: IntKind, start: usize) -> u64 {
    let w = kind.width();
    let mut v = 0u64;
    match kind {
        IntKind::U8 | IntKind::U16Be | IntKind::U24Be | IntKind::U32Be => {
            for i in 0..w {
                v = (v << 8) | buf[start + i] as u64;
            }
        }
        IntKind::U16Le | IntKind::U32Le => {
            for i in (0..w).rev() {
                v = (v << 8) | buf[start + i] as u64;
            }
        }
    }
    v
}


impl<'a> Enc<'a> {
    fn encode_inline_struct(
        &mut self,
        field: &Field,
        inner: &StructDef,
        hard_size: Option<usize>,
        value: Option<&Json>,
        buf: &mut Vec<u8>,
        path: &[String],
    ) -> Result<usize, EncodeError> {
        let value = value.unwrap_or(&Json::Null);
        let mut child_path = path.to_vec();
        child_path.push(field.name.clone());
        let mut scope = Scope::default();
        self.struct_values(inner, value, buf, &mut scope, &child_path, hard_size)
    }

    #[allow(clippy::too_many_arguments)]
    fn encode_struct_ref(
        &mut self,
        field: &Field,
        name: &str,
        size_expr: Option<&Expr>,
        value: Option<&Json>,
        buf: &mut Vec<u8>,
        path: &[String],
        len_patches: &mut Vec<LenPatch>,
        _struct_start: usize,
    ) -> Result<(), EncodeError> {
        let inner = self.p.find(name).expect("compile 保证").clone();
        let mut child_path = path.to_vec();
        child_path.push(field.name.clone());
        let value = value.unwrap_or(&Json::Null);

        let linked = size_expr.and_then(single_var);
        if linked.is_some() {
            // 先在独立缓冲区编码（内部校验和也已就绪），再用真实大小回填父长度字段。
            let mut tmp = Vec::new();
            let mut scope = Scope::default();
            let size =
                self.struct_values(&inner, value, &mut tmp, &mut scope, &child_path, None)?;
            if let Some(len_name) = linked {
                self.fill_len_patch(len_patches, &len_name, size as u64);
            }
            buf.extend_from_slice(&tmp);
        } else {
            let declared = match size_expr {
                Some(e) => eval_size(e, &Scope::default(), &child_path)?,
                None => None,
            };
            let mut scope = Scope::default();
            self.struct_values(&inner, value, buf, &mut scope, &child_path, declared)?;
        }
        let _ = field;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn encode_repeat(
        &mut self,
        field: &Field,
        count_expr: &Expr,
        body: &RepeatBody,
        value: Option<&Json>,
        _buf: &mut Vec<u8>,
        _scope: &mut Scope,
        path: &[String],
        len_patches: &mut Vec<LenPatch>,
        _struct_start: usize,
    ) -> Result<(), EncodeError> {
        let mut fpath = path.to_vec();
        fpath.push(field.name.clone());
        let arr = match value {
            Some(Json::Arr(a)) => a,
            Some(Json::Null) | None => &Vec::new(),
            _ => {
                return Err(EncodeError::at(
                    fpath,
                    format!("repeat {} 需要数组", field.name),
                ))
            }
        };
        let n = arr.len() as u64;
        // 计数字段回填
        if let Expr::Var(count_name) = count_expr {
            if let Some(p) = len_patches.iter_mut().find(|p| p.length_field == *count_name) {
                p.value_for = LengthTarget::RepeatCount(n);
            }
        }

        // 先在独立缓冲区里编码每个元素（体可能是定界结构）。
        let mut tmp = Vec::new();
        for (i, item) in arr.iter().enumerate() {
            let mut ipath = fpath.clone();
            ipath.push(format!("[{}]", i));
            match body {
                RepeatBody::Raw => {
                    let bytes = json_hex(Some(item), "repeat bytes 元素", &ipath)?;
                    if bytes.len() != 1 {
                        return Err(EncodeError::at(
                            ipath,
                            "repeat bytes 的每个元素必须是单个字节".to_string(),
                        ));
                    }
                    tmp.push(bytes[0]);
                }
                RepeatBody::StructRef(name) => {
                    let inner = self.p.find(name).expect("compile 保证").clone();
                    let mut scope = Scope::default();
                    self.struct_values(&inner, item, &mut tmp, &mut scope, &ipath, None)?;
                }
                RepeatBody::StructDef(inner) => {
                    let mut scope = Scope::default();
                    self.struct_values(inner, item, &mut tmp, &mut scope, &ipath, None)?;
                }
            }
        }
        _buf.extend_from_slice(&tmp);
        Ok(())
    }
}

fn expr_uses(e: &Expr, name: &str) -> bool {
    match e {
        Expr::Lit(_) => false,
        Expr::Var(n) => n == name,
        Expr::StartOf(n) | Expr::EndOf(n) => n == name,
        Expr::Bin(a, _, b) => expr_uses(a, name) || expr_uses(b, name),
    }
}

fn later_uses(f: &Field, name: &str) -> bool {
    if let Some(w) = &f.when {
        if expr_uses(w, name) {
            return true;
        }
    }
    match &f.kind {
        FieldKind::VarBytes(e) => expr_uses(e, name),
        FieldKind::StructRef(_, Some(e)) => expr_uses(e, name),
        FieldKind::Repeat(e, _) => expr_uses(e, name),
        FieldKind::Assert(e) => expr_uses(e, name),
        _ => false,
    }
}
