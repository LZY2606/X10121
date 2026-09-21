use super::Span;
use crate::spec::ChecksumAlgo;

/// A resolved coverage interval bound to the field that produced it.
#[derive(Debug, Clone, Copy)]
pub struct CoverSpan {
    pub span: Span,
}

impl CoverSpan {
    #[allow(dead_code)]
    pub fn new(span: Span) -> Self {
        CoverSpan { span }
    }
}

/// Compute a checksum over `data`, covering the union of `spans`. Overlapping
/// intervals count each covered byte exactly once. Bytes are visited in
/// ascending offset order. The checksum's own bytes must never be part of the
/// union (the parser excludes them).
pub fn compute_checksum(data: &[u8], spans: &[Span], algo: ChecksumAlgo) -> u64 {
    let mut covered = vec![false; data.len()];
    for sp in spans {
        let start = sp.start.min(data.len());
        let end = sp.end().min(data.len());
        for b in &mut covered[start..end] {
            *b = true;
        }
    }
    let bytes: Vec<u8> = data
        .iter()
        .zip(covered.iter())
        .filter(|(_, on)| **on)
        .map(|(b, _)| *b)
        .collect();

    match algo {
        ChecksumAlgo::Sum8 => bytes.iter().map(|b| *b as u64).sum::<u64>() & 0xff,
        ChecksumAlgo::Xor8 => bytes.iter().fold(0u8, |acc, b| acc ^ b) as u64,
        ChecksumAlgo::Sum16 => {
            let mut sum: u64 = 0;
            for pair in bytes.chunks(2) {
                let hi = pair[0] as u64;
                let lo = if pair.len() == 2 { pair[1] as u64 } else { 0 };
                sum = (sum + ((hi << 8) | lo)) & 0xffff;
            }
            sum
        }
        ChecksumAlgo::Xor16 => {
            let mut acc: u16 = 0;
            for pair in bytes.chunks(2) {
                let hi = pair[0] as u16;
                let lo = if pair.len() == 2 { pair[1] as u16 } else { 0 };
                acc ^= (hi << 8) | lo;
            }
            acc as u64
        }
    }
}
