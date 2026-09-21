#![allow(dead_code)]

use frame_lab::bytes::ByteWriter;
use frame_lab::parser;
use frame_lab::spec::ChecksumAlg;

/// 与内置演示协议同构的 TLV 帧生成器。
#[derive(Clone, Debug)]
pub struct DemoItem {
    pub tag: u8,
    pub value: Vec<u8>,
    pub children: Vec<DemoItem>,
}

impl DemoItem {
    pub fn simple(tag: u8, value: &[u8]) -> Self {
        DemoItem { tag, value: value.to_vec(), children: Vec::new() }
    }

    pub fn nested(children: Vec<DemoItem>) -> Self {
        DemoItem { tag: 2, value: vec![0xee], children }
    }

    fn write_body(w: &mut ByteWriter, items: &[DemoItem]) {
        w.u8(items.len() as u8);
        for item in items {
            w.u8(item.tag).u8(item.value.len() as u8).bytes(&item.value);
            if item.tag == 2 {
                let mut child = ByteWriter::new();
                Self::write_body(&mut child, &item.children);
                let payload = child.into_vec();
                w.u8(payload.len() as u8).bytes(&payload);
            } else {
                w.u8(0);
            }
        }
    }

    fn body_bytes(items: &[DemoItem]) -> Vec<u8> {
        let mut w = ByteWriter::new();
        Self::write_body(&mut w, items);
        w.into_vec()
    }
}

pub fn encode_frame(frame_id: u16, items: &[DemoItem], checksum_byte: Option<u8>) -> Vec<u8> {
    let body = DemoItem::body_bytes(items);
    let mut w = ByteWriter::new();
    w.u8(0xaa).u16_be(frame_id).u16_be(body.len() as u16).bytes(&body).u8(0xbb);
    let checksum = match checksum_byte {
        Some(b) => b,
        None => {
            // 覆盖 soi..=eoi，跳过 checksum 自身。
            parser::checksum_fix_byte(ChecksumAlg::Sum8, w.as_slice())
        }
    };
    w.u8(checksum);
    w.into_vec()
}

pub fn sample_frame() -> Vec<u8> {
    encode_frame(
        0x0001,
        &[
            DemoItem::simple(1, &[0x01, 0x02]),
            DemoItem::nested(vec![DemoItem::simple(3, &[0x09])]),
            DemoItem::simple(9, &[]),
        ],
        None,
    )
}

pub fn deep_nesting_frame(depth: usize) -> Vec<u8> {
    let mut item = DemoItem::simple(3, &[0x77]);
    for _ in 0..depth {
        item = DemoItem::nested(vec![item]);
    }
    encode_frame(0x0002, &[item], None)
}
