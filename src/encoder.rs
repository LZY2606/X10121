// 帧编码器：根据字段值 JSON 生成合法帧。
//
// 每个结构两阶段处理：
// 1) layout：int 全部先占位记录定位；bytes/struct/array 顺序写出并记录字段区间；
// 2) finalize：依次回填 长度/计数 int（引用同层前置 int，值来自后续 bytes/array）、
//    普通 int（显式值或 default）、校验和 int（按 cover/skip 计算，天然跳过自身）。

use crate::json::Value;
use crate::model::{ChecksumAlgo, Endian, Expr, Field, FieldKind, Protocol};

struct IntLoc {
    start: usize,
    width: usize,
}

struct Ctx {
    buf: Vec<u8>,
    ints: Vec<IntLoc>,
    used_defaults: Vec<String>,
}

fn put_int(buf: &mut [u8], start: usize, val: i128, width: usize, endian: Endian) {
    let u = val as u128;
    for i in 0..width {
        let byte = ((u >> (i * 8)) & 0xff) as u8;
        match endian {
            Endian::Big => buf[start + width - 1 - i] = byte,
            Endian::Little => buf[start + i] = byte,
        }
    }
}

fn check_range(val: i128, width: usize, signed: bool, where_: &str) -> Result<(), String> {
    let bits = width * 8;
    let (min, max): (i128, i128) = if signed {
        (-(1i128 << (bits - 1)), (1i128 << (bits - 1)) - 1)
    } else {
        (0, (1i128 << bits) - 1)
    };
    if val < min || val > max {
        return Err(format!(
            "{}: 整数值 {} 超出 {} 字节{}整数范围 [{},{}]",
            where_, val, width,
            if signed { "有符号" } else { "无符号" },
            min, max
        ));
    }
    Ok(())
}

fn value_int(v: &Value, where_: &[String]) -> Result<i128, String> {
    v.as_i128()
        .ok_or_else(|| format!("{}: 需要整数值", where_.join("/")))
}

fn arr_to_bytes(a: &[Value], where_: &[String]) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(a.len());
    for item in a {
        let n = item
            .as_i128()
            .ok_or_else(|| format!("{}: 字节数组元素必须是 0..=255 的整数", where_.join("/")))?;
        if !(0..=255).contains(&n) {
            return Err(format!("{}: 字节 {} 超出 0..=255", where_.join("/"), n));
        }
        out.push(n as u8);
    }
    Ok(out)
}

fn bytes_field_value(v: Option<&Value>, where_: &[String]) -> Result<Vec<u8>, String> {
    match v {
        Some(Value::Str(hex)) => crate::hash::unhex(hex)
            .ok_or_else(|| format!("{}: 不是合法十六进制字符串", where_.join("/"))),
        Some(Value::Arr(a)) => arr_to_bytes(a, where_),
        Some(other) => Err(format!(
            "{}: bytes 字段需要十六进制字符串或字节数组，得到 {}",
            where_.join("/"), other.type_name()
        )),
        None => Ok(Vec::new()),
    }
}

fn expr_base(e: &Expr) -> Option<&str> {
    match e {
        Expr::Ref(n) | Expr::RefMinus(n, _) => Some(n),
        Expr::Const(_) => None,
    }
}

pub struct EncodedFrame {
    pub bytes: Vec<u8>,
    pub used_defaults: Vec<String>,
}

pub fn encode(proto: &Protocol, input: &Value) -> Result<EncodedFrame, String> {
    let root_input = input
        .as_object()
        .ok_or_else(|| "编码输入必须是字段名到值的对象".to_string())?;
    let mut ctx = Ctx {
        buf: Vec::new(),
        ints: Vec::new(),
        used_defaults: Vec::new(),
    };
    let mut root_local: Vec<(String, i128)> = Vec::new();
    layout_struct(
        proto,
        &proto.root,
        root_input,
        &mut ctx,
        1,
        vec![proto.root.clone()],
        &mut root_local,
    )?;
    if ctx.buf.len() > proto.max_frame {
        return Err(format!(
            "编码结果 {} 字节超过 max_frame {}",
            ctx.buf.len(),
            proto.max_frame
        ));
    }
    Ok(EncodedFrame {
        bytes: ctx.buf,
        used_defaults: ctx.used_defaults,
    })
}

#[allow(clippy::too_many_arguments)]
fn layout_struct(
    proto: &Protocol,
    sname: &str,
    input: &[(String, Value)],
    ctx: &mut Ctx,
    depth: usize,
    path: Vec<String>,
    local: &mut Vec<(String, i128)>,
) -> Result<(), String> {
    if depth > proto.max_depth {
        return Err(format!(
            "depth-limit: 结构 {:?} 嵌套超过深度上限 {}",
            sname, proto.max_depth
        ));
    }
    let fields: Vec<Field> = proto.structs[sname].clone();
    let lookup = |name: &str| input.iter().find(|(k, _)| k == name).map(|(_, v)| v);

    // 记录本结构内各 int 占位（字段名、定位索引）以及各字段区间，供 finalize 使用。
    let mut int_placeholders: Vec<(String, usize)> = Vec::new();
    let mut ranges: Vec<(String, usize, usize)> = Vec::new();

    for field in &fields {
        let mut fpath = path.clone();
        fpath.push(field.name.clone());
        let start = ctx.buf.len();

        if let Some(wf) = &field.when_field {
            let dep = local.iter().rev().find(|(n, _)| n == wf).map(|(_, v)| *v);
            if dep != Some(field.when_equals as i128) {
                continue;
            }
        }

        match &field.kind {
            FieldKind::Int {
                bytes,
                ..
            } => {
                for _ in 0..*bytes {
                    ctx.buf.push(0);
                }
                let idx = ctx.ints.len();
                ctx.ints.push(IntLoc { start, width: *bytes });
                int_placeholders.push((field.name.clone(), idx));
                ranges.push((field.name.clone(), start, start + bytes));
            }
            FieldKind::Bytes { .. } => {
                let data = bytes_field_value(lookup(&field.name), &fpath)?;
                let end = start + data.len();
                ctx.buf.extend_from_slice(&data);
                ranges.push((field.name.clone(), start, end));
                local.push((field.name.clone(), data.len() as i128));
            }
            FieldKind::Struct(child) => {
                let child_input = match lookup(&field.name) {
                    Some(Value::Obj(o)) => o,
                    Some(Value::Null) | None => &Vec::new(),
                    Some(other) => {
                        return Err(format!(
                            "{}: struct 字段需要对象，得到 {}",
                            fpath.join("/"), other.type_name()
                        ))
                    }
                };
                layout_struct(
                    proto,
                    child,
                    child_input,
                    ctx,
                    depth + 1,
                    fpath,
                    &mut Vec::new(),
                )?;
                let end = ctx.buf.len();
                ranges.push((field.name.clone(), start, end));
            }
            FieldKind::Array { struct_name, .. } => {
                let items = match lookup(&field.name) {
                    Some(Value::Arr(a)) => a,
                    Some(Value::Null) | None => &Vec::new(),
                    Some(other) => {
                        return Err(format!(
                            "{}: array 字段需要数组，得到 {}",
                            fpath.join("/"), other.type_name()
                        ))
                    }
                };
                for (i, item) in items.iter().enumerate() {
                    let item_input = item.as_object().ok_or_else(|| {
                        format!("{}[{}]: 数组元素必须是对象", fpath.join("/"), i)
                    })?;
                    let mut ipath = fpath.clone();
                    ipath.push(format!("[{}]", i));
                    layout_struct(
                        proto,
                        struct_name,
                        item_input,
                        ctx,
                        depth + 1,
                        ipath,
                        &mut Vec::new(),
                    )?;
                }
                let end = ctx.buf.len();
                ranges.push((field.name.clone(), start, end));
                local.push((field.name.clone(), items.len() as i128));
            }
        }
    }

    let struct_end = ctx.buf.len();

    // ---- finalize：按字段声明顺序决定每个 int 的值 ----
    for field in &fields {
        let FieldKind::Int {
            bytes,
            signed,
            endian,
            default,
            checksum,
            ..
        } = &field.kind else {
            continue;
        };
        let mut fpath = path.clone();
        fpath.push(field.name.clone());
        let idx = *int_placeholders
            .iter()
            .find(|(n, _)| n == &field.name)
            .map(|(_, i)| i)
            .ok_or_else(|| format!("内部错误：丢失 int 占位 {}", field.name))?;
        let endian = endian.unwrap_or(proto.endian);

        if let Some(cs) = checksum {
            let val = compute_checksum(ctx, cs, field, &ranges, &fpath)?;
            check_range(val, *bytes, *signed, &fpath.join("/"))?;
            let loc = &ctx.ints[idx];
            put_int(&mut ctx.buf, loc.start, val, loc.width, endian);
            local.push((field.name.clone(), val));
            continue;
        }

        // 长度/计数派生：后续 bytes/array 是否以本字段为引用
        let mut derived: Option<i128> = None;
        for later in fields.iter().skip_while(|f| f.name != field.name).skip(1) {
            match &later.kind {
                FieldKind::Bytes { length: Some(e), remaining: false } => {
                    if expr_base(e) == Some(field.name.as_str()) {
                        let raw = ranges
                            .iter()
                            .find(|(n, _, _)| n == &later.name)
                            .map(|(_, a, b)| (*b - *a) as i128)
                            .unwrap_or(0);
                        derived = Some(apply_expr_inverse(e, raw));
                        break;
                    }
                }
                FieldKind::Array { count: e, .. } => {
                    if expr_base(e) == Some(field.name.as_str()) {
                        let n = local
                            .iter()
                            .rev()
                            .find(|(n, _)| n == &later.name)
                            .map(|(_, v)| *v)
                            .unwrap_or(0);
                        derived = Some(apply_expr_inverse(e, n));
                        break;
                    }
                }
                _ => {}
            }
        }

        let val = if let Some(v) = lookup(&field.name) {
            let given = value_int(v, &fpath)?;
            if let Some(d) = derived {
                if given != d {
                    return Err(format!(
                        "{}: 显式值 {} 与按后续字段派生出的值 {} 冲突",
                        fpath.join("/"), given, d
                    ));
                }
            }
            given
        } else if let Some(d) = derived {
            d
        } else if let Some(d) = default {
            ctx.used_defaults.push(fpath.join("/"));
            *d as i128
        } else {
            return Err(format!(
                "{}: 缺少字段值（未声明 default，且不是可派生的长度/计数字段）",
                fpath.join("/")
            ));
        };
        check_range(val, *bytes, *signed, &fpath.join("/"))?;
        let loc = &ctx.ints[idx];
        put_int(&mut ctx.buf, loc.start, val, loc.width, endian);
        local.push((field.name.clone(), val));
    }

    let _ = struct_end;
    Ok(())
}

/// 长度表达式的反解：length = $len - k  => len = raw + k。
fn apply_expr_inverse(e: &Expr, raw: i128) -> i128 {
    match e {
        Expr::Ref(_) | Expr::Const(_) => raw,
        Expr::RefMinus(_, k) => raw.saturating_add(*k as i128),
    }
}

fn compute_checksum(
    ctx: &Ctx,
    cs: &crate::model::ChecksumSpec,
    own_field: &Field,
    ranges: &[(String, usize, usize)],
    fpath: &[String],
) -> Result<i128, String> {
    let own: Vec<&str> = {
        let mut v = vec![own_field.name.as_str()];
        for s in &cs.skip {
            v.push(s.as_str());
        }
        v
    };
    let covered: Vec<&(String, usize, usize)> = match &cs.cover {
        Some(names) => names
            .iter()
            .filter_map(|name| ranges.iter().find(|(n, _, _)| n == name))
            .filter(|(n, _, _)| !own.contains(&n.as_str()))
            .collect(),
        None => {
            let own_pos = ranges
                .iter()
                .position(|(n, _, _)| n == &own_field.name)
                .unwrap_or(ranges.len());
            ranges[..own_pos]
                .iter()
                .filter(|(n, _, _)| !own.contains(&n.as_str()))
                .collect()
        }
    };
    let mut acc8: u16 = 0;
    let mut acc16: u32 = 0;
    let mut xor: u8 = 0;
    for (_, a, b) in &covered {
        let slice = &ctx.buf[*a..*b];
        match cs.algo {
            ChecksumAlgo::Sum8 => {
                for &x in slice {
                    acc8 = acc8.wrapping_add(x as u16);
                }
            }
            ChecksumAlgo::Xor8 => {
                for &x in slice {
                    xor ^= x;
                }
            }
            ChecksumAlgo::Sum16 => {
                for chunk in slice.chunks(2) {
                    let hi = chunk[0] as u32;
                    let lo = *chunk.get(1).unwrap_or(&0) as u32;
                    acc16 = acc16.wrapping_add((hi << 8) | lo);
                }
            }
        }
    }
    let _ = fpath;
    Ok(match cs.algo {
        ChecksumAlgo::Sum8 => (acc8 & 0xff) as i128,
        ChecksumAlgo::Xor8 => xor as i128,
        ChecksumAlgo::Sum16 => {
            let mut s = acc16;
            while (s >> 16) != 0 {
                s = (s & 0xffff) + (s >> 16);
            }
            (s & 0xffff) as i128
        }
    })
}
