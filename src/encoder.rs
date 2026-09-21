//! 帧编码器：根据结构化取值构造字节，并自动回填校验和。
//! 与解析器使用相同校验规则（默认跳过自身字段）。供测试/演示生成合法帧。

use crate::json::Json;
use crate::model::*;

pub struct Encoder<'a> {
    spec: &'a ProtocolSpec,
}

impl<'a> Encoder<'a> {
    pub fn new(spec: &'a ProtocolSpec) -> Self {
        Encoder { spec }
    }

    pub fn encode(&self, root: &Json) -> Result<Vec<u8>, String> {
        let mut buf = Vec::new();
        self.encode_struct(&self.spec.root, root, &mut buf, &mut Vec::new())?;
        Ok(buf)
    }

    fn encode_struct(
        &self,
        ty: &str,
        val: &Json,
        out: &mut Vec<u8>,
        ends: &mut Vec<(String, u64)>,
    ) -> Result<(), String> {
        let sdef = self
            .spec
            .structs
            .get(ty)
            .ok_or_else(|| format!("未知结构体 {}", ty))?;
        for fdef in &sdef.fields {
            self.encode_field(fdef, val, out, ends)?;
            ends.push((fdef.name().to_string(), out.len() as u64));
        }
        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    fn encode_field(
        &self,
        fdef: &FieldDef,
        val: &Json,
        out: &mut Vec<u8>,
        ends: &mut Vec<(String, u64)>,
    ) -> Result<(), String> {
        let obj = val.as_object();
        let get = |name: &str| -> &Json {
            obj.and_then(|m| m.get(name)).unwrap_or(&Json::Null)
        };
        match fdef {
            FieldDef::Int {
                name,
                width,
                endian,
                signed: _,
                expect: _,
            } => {
                let v = get(name).as_i64().unwrap_or(0) as u64;
                write_int(out, v, *width, *endian);
            }
            FieldDef::Bytes { name, .. } => {
                let hex = get(name).as_str().unwrap_or("");
                out.extend_from_slice(&decode_hex(hex)?);
            }
            FieldDef::Payload {
                name,
                length_field,
            } => {
                let payload = decode_hex(get(name).as_str().unwrap_or(""))?;
                let want = get(length_field).as_u64().unwrap_or(payload.len() as u64);
                if want as usize != payload.len() {
                    return Err(format!(
                        "payload {} 长度 {} 与长度字段 {} 不一致",
                        name,
                        payload.len(),
                        want
                    ));
                }
                out.extend_from_slice(&payload);
            }
            FieldDef::Struct { name, ty, .. } => {
                self.encode_struct(ty, get(name), out, &mut Vec::new())?;
            }
            FieldDef::Vector { name, element, .. } => {
                let arr = get(name).as_array().cloned().unwrap_or_default();
                for item in &arr {
                    self.encode_field(element, item, out, &mut Vec::new())?;
                }
            }
            FieldDef::Switch {
                name,
                cases,
                fallback,
                ..
            } => {
                let case_obj = get(name);
                let sub = case_obj
                    .as_object()
                    .ok_or_else(|| format!("switch {} 需要对象", name))?;
                let key = sub
                    .get("case")
                    .and_then(|v| v.as_i64())
                    .map(|v| v.to_string());
                let fields = key
                    .as_ref()
                    .and_then(|k| cases.get(k))
                    .or(fallback.as_ref())
                    .map(|c| &c.fields)
                    .ok_or_else(|| format!("switch {} 无匹配分支", name))?;
                let body = sub
                    .get("value")
                    .and_then(|v| v.as_object())
                    .ok_or_else(|| format!("switch {} 需要 value 对象", name))?;
                for cf in fields {
                    self.encode_field(cf, &Json::Obj(body.clone()), out, &mut Vec::new())?;
                }
            }
            FieldDef::Checksum {
                name,
                width,
                algorithm,
                endian,
                start,
                end,
            } => {
                if let Some(v) = get(name).as_u64() {
                    write_int(out, v, *width, *endian);
                    return Ok(());
                }
                let s0 = start.unwrap_or(0) as usize;
                let cover_end = match end {
                    None | Some(EndRef::StructEnd) => out.len(),
                    Some(EndRef::Field(field)) => ends
                        .iter()
                        .rev()
                        .find(|(n, _)| n == field)
                        .map(|(_, e)| *e as usize)
                        .unwrap_or(out.len()),
                };
                let lo = s0.min(cover_end);
                let cs = crate::parser::checksum_of(*algorithm, &out[lo..cover_end]);
                write_int(out, cs, *width, *endian);
            }
        }
        Ok(())
    }
}

fn write_int(out: &mut Vec<u8>, value: u64, width: u32, endian: Endian) {
    let mut bytes = Vec::with_capacity(width as usize);
    for i in 0..width {
        let shift = ((width - 1 - i) * 8) as u32;
        bytes.push((value >> shift) as u8);
    }
    if matches!(endian, Endian::Le) {
        bytes.reverse();
    }
    out.extend_from_slice(&bytes);
}

pub fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    let clean: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if clean.len() % 2 != 0 {
        return Err("十六进制长度必须为偶数".into());
    }
    (0..clean.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&clean[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

pub fn encode_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}
