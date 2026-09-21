//! 合法帧编码器：与解析器对称，用于生成测试数据与界面编码。
//!
//! - 长度字段先以 0 占位，子字段全部落位后回填 payload/bytes 长度（含 adjust）；
//! - 校验和在结构结束时就地计算，支持覆盖区间与跳过自身。

use crate::error::{LabError, LabResult};
use crate::protocol::{
    json_as_u64, ChecksumAlgo, CondOp, Field, LengthOf, Protocol, When,
};
use serde_json::Value;
use std::collections::BTreeMap;

struct Scope {
    /// 字段名 -> (起始, 结束, 宽度, 大端)；同名字段以后者为准（协议禁止重名）。
    ranges: BTreeMap<String, (usize, usize, usize, bool)>,
}

#[derive(Clone)]
struct LenPatch {
    at: usize,
    width: usize,
    big_endian: bool,
    scope_index: usize,
    target: String,
    adjust: i64,
}

fn empty_scope() -> Scope {
    Scope {
        ranges: BTreeMap::new(),
    }
}

#[derive(Clone)]
struct ChecksumTask {
    at: usize,
    width: usize,
    algo: ChecksumAlgo,
    skip_self: bool,
    /// (起始, 结束) 绝对偏移区间。
    ranges: Vec<(usize, usize)>,
}

struct Builder {
    buf: Vec<u8>,
    scopes: Vec<Scope>,
    len_patches: Vec<LenPatch>,
    checksums: Vec<ChecksumTask>,
}

pub fn encode(protocol: &Protocol, values: &Value) -> LabResult<Vec<u8>> {
    protocol.validate()?;
    let mut builder = Builder {
        buf: Vec::new(),
        scopes: vec![empty_scope()],
        len_patches: Vec::new(),
        checksums: Vec::new(),
    };
    encode_struct(protocol, &protocol.root.clone(), values, 0, &mut builder, 0)?;

    // 先回填长度字段（后写先填，保证内层先确定）。
    for patch in builder.len_patches.clone().into_iter().rev() {
        let (s, e, _, _) = *builder.scopes[patch.scope_index]
            .ranges
            .get(&patch.target)
            .ok_or_else(|| LabError::new(format!("编码时找不到长度目标 '{}'", patch.target)))?;
        let length = (e - s) as i64 + patch.adjust;
        if length < 0 {
            return Err(LabError::new(format!("长度回填为负：{length}")));
        }
        write_int(&mut builder.buf, patch.at, patch.width, length as u64, patch.big_endian);
    }
    // 长度字段就位后再计算校验和。
    for task in builder.checksums.clone() {
        apply_checksum(&mut builder.buf, &task);
    }
    Ok(builder.buf)
}

#[allow(clippy::too_many_arguments)]
fn encode_struct(
    protocol: &Protocol,
    sname: &str,
    values: &Value,
    depth: usize,
    builder: &mut Builder,
    scope_index: usize,
) -> LabResult<()> {
    let fields = protocol
        .structs
        .get(sname)
        .ok_or_else(|| LabError::new(format!("结构 '{sname}' 不存在")))?
        .clone();
    for field in &fields {
        if !conditions_hold(field.when(), values, builder, scope_index)? {
            continue;
        }
        encode_field(protocol, sname, field, values, depth, builder, scope_index)?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn encode_field(
    protocol: &Protocol,
    sname: &str,
    field: &Field,
    values: &Value,
    depth: usize,
    builder: &mut Builder,
    scope_index: usize,
) -> LabResult<()> {
    match field {
        Field::Int {
            name,
            width,
            endian,
            expect,
            ..
        } => {
            let start = builder.buf.len();
            let is_len_field = struct_fields(protocol, sname)
                .iter()
                .any(|f| matches!(&f, Field::Bytes { len, .. } | Field::Payload { len, .. }
                    if matches!(len, LengthOf::Field { field, .. } if field == name)));
            let value = match values.get(name).and_then(value_u64) {
                Some(v) => v,
                None => match expect.as_ref().and_then(json_as_u64) {
                    Some(v) => v,
                    None if is_len_field => 0,
                    None => {
                        return Err(LabError::new(format!("字段 '{name}' 缺少整数值")));
                    }
                },
            };
            builder
                .buf
                .extend_from_slice(&int_bytes(value, *width, *endian));
            let end = builder.buf.len();
            record_range(
                builder,
                scope_index,
                name,
                start,
                end,
                *width,
                matches!(endian, crate::protocol::Endian::Big),
            );
        }
        Field::Bytes { name, len, .. } => {
            let start = builder.buf.len();
            let bytes = match values.get(name) {
                Some(Value::String(hex)) => crate::hex::decode(hex)
                    .map_err(|e| LabError::new(format!("字段 '{name}' 十六进制非法: {e}")))?,
                Some(Value::Array(arr)) => arr
                    .iter()
                    .map(|v| v.as_u64().map(|n| n as u8).ok_or("字节数组元素非法"))
                    .collect::<Result<Vec<u8>, _>>()
                    .map_err(|e| LabError::new(format!("字段 '{name}': {e}")))?,
                Some(Value::Null) | None => Vec::new(),
                _ => return Err(LabError::new(format!("字段 '{name}' 需要十六进制字符串"))),
            };
            register_len(builder, len, scope_index, name)?;
            builder.buf.extend_from_slice(&bytes);
            let end = builder.buf.len();
            record_range(builder, scope_index, name, start, end, bytes.len(), true);
        }
        Field::Payload {
            name,
            len,
            struct_ref,
        } => {
            let start = builder.buf.len();
            register_len(builder, len, scope_index, name)?;
            if let Some(r) = struct_ref {
                if depth >= protocol.max_depth {
                    return Err(LabError::new(format!(
                        "编码递归深度超过上限 {}",
                        protocol.max_depth
                    )));
                }
                builder.scopes.push(Scope {
                    ranges: BTreeMap::new(),
                });
                let child_scope = builder.scopes.len() - 1;
            let child_values = values.get(name).unwrap_or(&Value::Null);
            encode_struct(
                protocol,
                r,
                child_values,
                depth + 1,
                builder,
                child_scope,
            )?;
            } else {
                if let Some(Value::String(hex)) = values.get(name) {
                    let bytes = crate::hex::decode(hex)
                        .map_err(|e| LabError::new(format!("字段 '{name}' 十六进制非法: {e}")))?;
                    builder.buf.extend_from_slice(&bytes);
                }
            }
            let end = builder.buf.len();
            record_range(builder, scope_index, name, start, end, end - start, true);
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
            let start = builder.buf.len();
            builder.scopes.push(empty_scope());
            let child_scope = builder.scopes.len() - 1;
            let next_depth = if matches!(field, Field::Ref { .. }) {
                depth + 1
            } else {
                depth
            };
            if next_depth > protocol.max_depth {
                return Err(LabError::new(format!(
                    "编码递归深度超过上限 {}",
                    protocol.max_depth
                )));
            }
            let child_values = values.get(name).unwrap_or(&Value::Null);
            encode_struct(
                protocol,
                struct_ref,
                child_values,
                next_depth,
                builder,
                child_scope,
            )?;
            let end = builder.buf.len();
            record_range(builder, scope_index, name, start, end, end - start, true);
        }
        Field::Checksum {
            name,
            width,
            algo,
            covers,
            skip_self,
            ..
        } => {
            let start = builder.buf.len();
            builder.buf.extend(std::iter::repeat_n(0u8, *width));
            let end = builder.buf.len();
            record_range(builder, scope_index, name, start, end, *width, true);
            let ranges = if covers.is_empty() {
                // 覆盖整个父结构：当前作用域从第一个字段到最后一个字段。
                match (
                    builder.scopes[scope_index]
                        .ranges
                        .values()
                        .min_by_key(|(s, _, _, _)| *s),
                    builder.scopes[scope_index]
                        .ranges
                        .values()
                        .max_by_key(|(_, e, _, _)| *e),
                ) {
                    (Some((fs, _, _, _)), Some((_, le, _, _))) => vec![(*fs, *le)],
                    _ => Vec::new(),
                }
            } else {
                covers
                    .iter()
                    .filter_map(|c| {
                        builder.scopes[scope_index]
                            .ranges
                            .get(c)
                            .map(|(s, e, _, _)| (*s, *e))
                    })
                    .collect()
            };
            builder.checksums.push(ChecksumTask {
                at: start,
                width: *width,
                algo: *algo,
                skip_self: *skip_self,
                ranges,
            });
        }
    }
    Ok(())
}

fn record_range(
    builder: &mut Builder,
    scope_index: usize,
    name: &str,
    start: usize,
    end: usize,
    width: usize,
    big_endian: bool,
) {
    builder.scopes[scope_index]
        .ranges
        .insert(name.to_string(), (start, end, width, big_endian));
}

fn register_len(
    builder: &mut Builder,
    len: &LengthOf,
    scope_index: usize,
    target: &str,
) -> LabResult<()> {
    if let LengthOf::Field { field, adjust } = len {
        let (at, _, width, big_endian) = builder
            .scopes[scope_index]
            .ranges
            .get(field)
            .copied()
            .ok_or_else(|| LabError::new(format!("长度字段 '{field}' 必须先于 '{target}' 出现")))?;
        builder.len_patches.push(LenPatch {
            at,
            width,
            big_endian,
            scope_index,
            target: target.to_string(),
            adjust: *adjust,
        });
    }
    Ok(())
}

fn value_u64(v: &Value) -> Option<u64> {
    match v {
        Value::Number(n) => n.as_u64(),
        Value::Object(map) => map.get("int").and_then(value_u64),
        _ => None,
    }
}

fn struct_fields<'a>(protocol: &'a Protocol, sname: &str) -> &'a [Field] {
    protocol.structs.get(sname).map(Vec::as_slice).unwrap_or(&[])
}

fn int_bytes(value: u64, width: usize, endian: crate::protocol::Endian) -> Vec<u8> {
    endian.write_u64(value, width)
}

fn write_int(buf: &mut [u8], at: usize, width: usize, value: u64, big_endian: bool) {
    let endian = if big_endian {
        crate::protocol::Endian::Big
    } else {
        crate::protocol::Endian::Little
    };
    buf[at..at + width].copy_from_slice(&endian.write_u64(value, width));
}

fn conditions_hold(
    whens: &[When],
    values: &Value,
    builder: &Builder,
    scope_index: usize,
) -> LabResult<bool> {
    for w in whens {
        let parts: Vec<&str> = w.field.split('.').collect();
        let actual_json = values.get(parts[0]).cloned().unwrap_or(Value::Null);
        let actual = value_u64(&actual_json);
        // 已落盘的整数字段优先（长度字段尚未回填时仍可能为占位 0）。
        let actual = actual.or_else(|| {
            let (s, e, _, big_endian) = *builder.scopes[scope_index].ranges.get(parts[0])?;
            let bytes = &builder.buf[s..e];
            let endian = if big_endian {
                crate::protocol::Endian::Big
            } else {
                crate::protocol::Endian::Little
            };
            Some(endian.read_u64(bytes))
        });
        let want = json_as_u64(&w.value);
        match (actual, want) {
            (Some(a), Some(b)) => {
                let ok = match w.op {
                    CondOp::Eq => a == b,
                    CondOp::Ne => a != b,
                    CondOp::Lt => a < b,
                    CondOp::Le => a <= b,
                    CondOp::Gt => a > b,
                    CondOp::Ge => a >= b,
                };
                if !ok {
                    return Ok(false);
                }
            }
            _ => return Ok(false),
        }
    }
    Ok(true)
}

fn apply_checksum(buf: &mut [u8], task: &ChecksumTask) {
    let value = compute(buf, task);
    match (task.algo, task.width) {
        (ChecksumAlgo::Sum8, 1) => buf[task.at] = value as u8,
        (ChecksumAlgo::Xor8, 1) => buf[task.at] = value as u8,
        (ChecksumAlgo::Sum16Be, 2) => {
            buf[task.at] = (value >> 8) as u8;
            buf[task.at + 1] = value as u8;
        }
        _ => {}
    }
}

fn compute(buf: &[u8], task: &ChecksumTask) -> u64 {
    let pieces = |start: usize, end: usize| -> Vec<(usize, usize)> {
        if !task.skip_self {
            return vec![(start, end)];
        }
        let cs_end = task.at + task.width;
        if task.at >= end || cs_end <= start {
            vec![(start, end)]
        } else {
            let mut out = Vec::new();
            if task.at > start {
                out.push((start, task.at));
            }
            if cs_end < end {
                out.push((cs_end, end));
            }
            out
        }
    };

    match task.algo {
        ChecksumAlgo::Sum8 => {
            let mut acc = 0u64;
            for (s, e) in &task.ranges {
                for (rs, re) in pieces(*s, *e) {
                    for b in &buf[rs..re] {
                        acc = (acc + *b as u64) & 0xff;
                    }
                }
            }
            acc
        }
        ChecksumAlgo::Xor8 => {
            let mut acc = 0u8;
            for (s, e) in &task.ranges {
                for (rs, re) in pieces(*s, *e) {
                    for b in &buf[rs..re] {
                        acc ^= b;
                    }
                }
            }
            acc as u64
        }
        ChecksumAlgo::Sum16Be => {
            let mut raw: Vec<u8> = Vec::new();
            for (s, e) in &task.ranges {
                for (rs, re) in pieces(*s, *e) {
                    raw.extend_from_slice(&buf[rs..re]);
                }
            }
            if raw.len() % 2 == 1 {
                raw.push(0);
            }
            let mut sum = 0u64;
            for pair in raw.chunks_exact(2) {
                sum = (sum + u16::from_be_bytes([pair[0], pair[1]]) as u64) & 0xffff;
            }
            sum
        }
    }
}
