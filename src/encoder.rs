//! 与解析器对称的编码器：从字段值 JSON 生成字节流。
//! - 整数：显式 value，缺省 0；checksum 字段在结构收尾时自动计算（支持自排除）
//! - bytes：十六进制值，长度必须与 length 配置一致
//! - 条件结构：按 when 字段当前值决定是否出现
//! - 词法作用域栈：长度/条件引用先查当前结构，再查祖先结构
use crate::json::Json;
use crate::spec::{Algo, ArrayItem, Endian, Field, FieldKind, LengthSpec, Spec, StructDef};

pub fn encode(spec: &Spec, values: &Json) -> Result<Vec<u8>, String> {
    let root = spec.get(&spec.root).ok_or_else(|| "根结构不存在".to_string())?;
    let mut buf = Vec::new();
    let mut ctx = Ctx { scopes: vec![Scope::new()], global_spans: Vec::new() };
    encode_struct(spec, root, values, &mut buf, &mut ctx)?;
    Ok(buf)
}

struct Scope {
    ints: Vec<(String, i64)>,
    spans: Vec<(String, (usize, usize))>,
}

impl Scope {
    fn new() -> Scope {
        Scope { ints: Vec::new(), spans: Vec::new() }
    }
}

struct Ctx {
    scopes: Vec<Scope>,
    /// 已编码字段的平面区间映射，供校验和覆盖标记引用后代结构字段
    global_spans: Vec<(String, (usize, usize))>,
}

impl Ctx {
    fn lookup_int(&self, name: &str) -> Option<i64> {
        for sc in self.scopes.iter().rev() {
            for (k, v) in sc.ints.iter().rev() {
                if k == name {
                    return Some(*v);
                }
            }
        }
        None
    }
    fn put_int(&mut self, name: &str, v: i64) {
        self.scopes.last_mut().unwrap().ints.push((name.to_string(), v));
    }
    fn put_span(&mut self, name: &str, s: usize, e: usize) {
        self.scopes.last_mut().unwrap().spans.push((name.to_string(), (s, e)));
        self.global_spans.push((name.to_string(), (s, e)));
    }
    /// 长度引用只允许在“当前结构”的作用域内解析（不能看到祖先字段）。
    fn resolve_local(&self, ls: &LengthSpec) -> Result<i64, String> {
        match ls {
            LengthSpec::Fixed(n) => Ok(*n),
            LengthSpec::Field { name, offset } => self
                .scopes
                .last()
                .and_then(|sc| sc.ints.iter().rev().find(|(k, _)| k == name).map(|(_, v)| *v + offset))
                .ok_or_else(|| format!("长度引用字段 {name} 不在当前结构内")),
        }
    }
}

fn field_value<'a>(values: &'a Json, name: &str) -> Option<&'a Json> {
    values.get(name)
}

fn int_of(v: &Json) -> Option<i64> {
    match v {
        Json::Int(n) => Some(*n),
        Json::Str(s) => s.trim().parse().ok(),
        _ => None,
    }
}

fn write_int(buf: &mut Vec<u8>, v: i64, width: usize, endian: Endian) {
    let mut raw = Vec::with_capacity(width);
    let mut x = v as u64;
    for _ in 0..width {
        raw.push((x & 0xFF) as u8);
        x >>= 8;
    }
    match endian {
        Endian::Le => buf.extend_from_slice(&raw),
        Endian::Be => {
            raw.reverse();
            buf.extend_from_slice(&raw);
        }
    }
}

fn encode_struct(
    spec: &Spec,
    sd: &StructDef,
    values: &Json,
    buf: &mut Vec<u8>,
    ctx: &mut Ctx,
) -> Result<(), String> {
    let start = buf.len();
    ctx.scopes.push(Scope::new());
    let mut field_spans: Vec<(String, usize, usize)> = Vec::new();

    for field in &sd.fields {
        if let FieldKind::Struct { when: Some(w), .. } = &field.kind {
            match ctx.lookup_int(&w.field) {
                Some(v) if v == w.eq => {}
                _ => continue,
            }
        }
        let fv = field_value(values, &field.name);
        let fstart = buf.len();
        encode_field(spec, field, fv, buf, ctx)?;
        let fend = buf.len();
        ctx.put_span(&field.name, fstart, fend);
        field_spans.push((field.name.clone(), fstart, fend));
    }

    // 1) 解析 length_ref 硬边界；先只补齐（不截断），保证末尾校验字段仍在缓冲区内
    let mut hard_end: Option<usize> = None;
    if let Some(lr) = &sd.length_ref {
        if let Ok(v) = ctx.resolve_local(lr) {
            let off = if let LengthSpec::Field { offset, .. } = lr { *offset } else { 0 };
            let hard = (start as i64 + v + off) as usize;
            hard_end = Some(hard);
            if buf.len() < hard {
                buf.resize(hard, 0);
            }
        }
    }

    // 2) 结构闭合后再计算校验和；覆盖标记可引用本结构或后代结构的字段
    for field in &sd.fields {
        let FieldKind::Int { checksum: Some(cs), width, .. } = &field.kind else {
            continue;
        };
        let Some((fs, fe)) = field_spans
            .iter()
            .find(|(n, _, _)| n == &field.name)
            .map(|(_, s, e)| (*s, *e))
        else {
            continue;
        };
        let mut lo = usize::MAX;
        let mut hi = 0usize;
        for mark in &cs.covers {
            let pos: usize = if mark == "@start" {
                start
            } else if mark == "@end" {
                hard_end.unwrap_or(buf.len())
            } else if let Some((_, (s, _))) =
                ctx.global_spans.iter().rev().find(|(k, _)| k == mark)
            {
                *s
            } else {
                return Err(format!("校验和覆盖标记 {mark} 无法定位"));
            };
            lo = lo.min(pos);
            hi = hi.max(pos);
        }
        if cs.skip_self {
            for b in buf.iter_mut().take(fe).skip(fs) {
                *b = 0;
            }
        }
        let mut sum: u64 = 0;
        let mut xor: u8 = 0;
        for (i, b) in buf.iter().enumerate().take(hi).skip(lo) {
            let in_self = cs.skip_self && i >= fs && i < fe;
            if !in_self {
                sum = (sum + *b as u64) & 0xFF;
                xor ^= *b;
            }
        }
        let val = match cs.algo {
            Algo::Sum8 => sum as u8,
            Algo::Xor8 => xor,
        };
        if *width != 1 {
            return Err(format!("校验和字段 {} 宽度必须为 1 字节", field.name));
        }
        if fs < buf.len() {
            buf[fs] = val;
        } else {
            return Err(format!(
                "校验和字段 {} 的位置 {fs} 落在结构边界 {} 之外（检查 length_ref 是否包含校验字段）",
                field.name,
                buf.len()
            ));
        }
    }

    // 3) 校验和写回后再裁剪到硬边界
    if let Some(hard) = hard_end {
        if buf.len() > hard {
            buf.truncate(hard);
        }
    }

    ctx.scopes.pop();
    Ok(())
}

fn encode_field(
    spec: &Spec,
    field: &Field,
    v: Option<&Json>,
    buf: &mut Vec<u8>,
    ctx: &mut Ctx,
) -> Result<(), String> {
    match &field.kind {
        FieldKind::Int { width, endian, checksum, expect_const, .. } => {
            let val = if let Some(c) = expect_const {
                *c
            } else if checksum.is_some() {
                0
            } else {
                v.and_then(int_of).unwrap_or(0)
            };
            write_int(buf, val, *width, *endian);
            ctx.put_int(&field.name, val);
            Ok(())
        }
        FieldKind::Bytes { length } => {
            let n = ctx.resolve_local(length)? as usize;
            let data = match v.and_then(|x| x.as_str()) {
                Some(hex) => crate::hexutil::decode_hex(hex)?,
                None => vec![0u8; n],
            };
            if data.len() != n {
                return Err(format!(
                    "字节字段 {} 提供了 {} 字节，但长度声明为 {n}",
                    field.name,
                    data.len()
                ));
            }
            buf.extend_from_slice(&data);
            Ok(())
        }
        FieldKind::Struct { struct_name, .. } => {
            let sd = spec.get(struct_name).ok_or_else(|| format!("结构 {struct_name} 不存在"))?;
            let sub = v.cloned().unwrap_or(Json::obj());
            encode_struct(spec, sd, &sub, buf, ctx)
        }
        FieldKind::Array { count, item } => {
            let n = ctx.resolve_local(count)? as usize;
            let items = v.and_then(|x| x.as_array()).cloned().unwrap_or_default();
            if items.len() != n {
                return Err(format!(
                    "数组字段 {} 提供了 {} 项，但计数声明为 {n}",
                    field.name,
                    items.len()
                ));
            }
            for itemv in &items {
                match item {
                    ArrayItem::Int { width, endian, signed } => {
                        let val = int_of(itemv).unwrap_or(0);
                        let _ = signed;
                        write_int(buf, val, *width, *endian);
                    }
                    ArrayItem::Bytes { length } => {
                        let k = ctx.resolve_local(length)? as usize;
                        let data = match itemv.as_str() {
                            Some(hex) => crate::hexutil::decode_hex(hex)?,
                            None => vec![0u8; k],
                        };
                        if data.len() != k {
                            return Err(format!("数组 bytes 项长度应为 {k}，实际 {}", data.len()));
                        }
                        buf.extend_from_slice(&data);
                    }
                    ArrayItem::Struct { struct_name } => {
                        let sd = spec.get(struct_name).unwrap();
                        encode_struct(spec, sd, itemv, buf, ctx)?;
                    }
                }
            }
            Ok(())
        }
    }
}
