#![allow(dead_code)]
use framelab::encoder::Encoder;
use framelab::json::{obj, Json};
use framelab::model::ProtocolSpec;
use framelab::store::Store;

pub fn temp_dir(tag: &str) -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("frame-lab-test-{}-{}", tag, nanos));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

pub fn demo_spec() -> ProtocolSpec {
    framelab::samples::demo_spec()
}

pub fn tlv_spec() -> ProtocolSpec {
    framelab::samples::tlv_spec()
}

/// 生成一个合法演示帧：type 随机，payload 随机。
pub fn gen_demo_frame(seed: u64) -> Vec<u8> {
    let spec = demo_spec();
    let mut rng = Rng::new(seed);
    let typ = 1 + (rng.next() % 2); // 1 或 2，触发条件分支
    let plen = (rng.next() % 20) as usize;
    let payload: Vec<u8> = (0..plen).map(|_| rng.next() as u8).collect();
    let magic = 0xBEADu64;
    let seq = rng.next() % 0xffff;
    let mut pairs = vec![
        ("magic", Json::from_u64(magic)),
        ("type", Json::from_u64(typ)),
        ("seq", Json::from_u64(seq)),
        ("len", Json::from_u64(plen as u64)),
        ("body", Json::string(framelab::encoder::encode_hex(&payload))),
    ];
    if typ == 1 {
        pairs.push((
            "tail",
            obj(vec![
                ("case", Json::from_u64(1)),
                (
                    "value",
                    obj(vec![
                        ("code", Json::from_u64(rng.next() % 256)),
                        ("mask", Json::from_u64(rng.next() % 256)),
                    ]),
                ),
            ]),
        ));
    } else {
        pairs.push((
            "tail",
            obj(vec![
                ("case", Json::from_u64(2)),
                (
                    "value",
                    obj(vec![(
                        "meta",
                        obj(vec![
                            ("ver", Json::from_u64(1)),
                            ("flags", Json::from_u64(rng.next() % 256)),
                            ("idx", Json::from_u64(rng.next() % 256)),
                        ]),
                    )]),
                ),
            ]),
        ));
    }
    let value = obj(pairs);
    Encoder::new(&spec).encode(&value).expect("合法帧必须可编码")
}

/// 生成合法递归 TLV 帧（嵌套深度受 max_depth 约束）。
pub fn gen_tlv_frame(seed: u64, depth: u32) -> Vec<u8> {
    let mut rng = Rng::new(seed);
    tlv_rec(&mut rng, depth)
}

fn tlv_rec(rng: &mut Rng, depth: u32) -> Vec<u8> {
    if depth == 0 || rng.next() % 3 == 0 {
        let n = 1 + (rng.next() % 6) as usize;
        let body: Vec<u8> = (0..n).map(|_| rng.next() as u8).collect();
        let mut v = vec![2u8, body.len() as u8];
        v.extend(body);
        v
    } else {
        let child_count = 1 + rng.next() % 2;
        let mut body = Vec::new();
        for _ in 0..child_count {
            body.extend(tlv_rec(rng, depth.saturating_sub(1)));
        }
        let mut v = vec![1u8, body.len() as u8];
        v.extend(body);
        v
    }
}

pub struct Rng {
    state: u64,
}
impl Rng {
    pub fn new(seed: u64) -> Self {
        Rng {
            state: seed.max(1).wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407),
        }
    }
    pub fn next(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.state = x;
        x.wrapping_mul(0x2545F4914F6CDD1D) >> 32
    }
}

pub struct ClockGuard {
    pub store: Store,
    pub dir: std::path::PathBuf,
}
impl Drop for ClockGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

pub fn fresh_store(tag: &str) -> ClockGuard {
    let dir = temp_dir(tag);
    let store = Store::open(&dir).unwrap();
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    let t = Arc::new(AtomicU64::new(1_700_000_000));
    let t2 = Arc::clone(&t);
    store.set_clock(move || {
        t2.fetch_add(1, Ordering::Relaxed) + 1
    });
    ClockGuard { store, dir }
}
