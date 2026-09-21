//! Blob deduplication, immutable version binding and export/import replay.

mod common;

use frame_lab::spec::{RawSpec, Spec};
use frame_lab::store::Store;
use std::time::{SystemTime, UNIX_EPOCH};

fn temp_store() -> Store {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let dir = std::env::temp_dir().join(format!("frame-lab-test-{}-{}", std::process::id(), nanos));
    Store::open(&dir).unwrap()
}

#[test]
fn identical_samples_share_blob_but_have_independent_sessions() {
    let store = temp_store();
    let spec = common::demo_spec();
    store.put_protocol("demo").unwrap();
    let version = store
        .save_version("demo", spec.raw.clone(), "v1", None)
        .unwrap();
    let frame = common::legal_demo_frame(&[1, 2, 3], 0);

    let s1 = store.create_session("demo", &version.version_hash, &frame, "note A").unwrap();
    let s2 = store.create_session("demo", &version.version_hash, &frame, "note B").unwrap();
    assert_eq!(s1.blob_hash, s2.blob_hash);
    assert_ne!(s1.id, s2.id);
    assert_eq!(s1.note, "note A");
    assert_eq!(s2.note, "note B");

    // Updating one note never touches the other.
    store.update_note(&s1.id, "changed").unwrap();
    assert_eq!(store.get_session(&s2.id).unwrap().note, "note B");
}

#[test]
fn exported_bundle_reimports_deterministically() {
    let store_a = temp_store();
    let spec = common::demo_spec();
    store_a.put_protocol("demo").unwrap();
    let version = store_a.save_version("demo", spec.raw.clone(), "v1", None).unwrap();
    let frame = common::legal_demo_frame(&[9, 8, 7, 6, 5], 2);
    let session = store_a
        .create_session("demo", &version.version_hash, &frame, "export me")
        .unwrap();
    let bundle = store_a.export_session(&session.id).unwrap();

    // Fresh repository: both version and blob are missing, but import restores
    // them and the session replays identically.
    let store_b = temp_store();
    let report = store_b.import_bundle(bundle.clone()).unwrap();
    assert!(report.replay_consistent);
    assert!(!report.version_present);
    assert!(!report.reused_blob);

    let imported = store_b.get_session(&report.session_id).unwrap();
    assert_eq!(imported.version_hash, version.version_hash);
    assert_eq!(imported.blob_hash, session.blob_hash);
    assert_eq!(imported.note, "export me");
    assert_eq!(
        frame_lab::spec::canonical_json(&imported.result),
        frame_lab::spec::canonical_json(&session.result)
    );
    assert_eq!(
        frame_lab::spec::canonical_json(&imported.summary),
        frame_lab::spec::canonical_json(&session.summary)
    );

    // Importing again reuses the blob and keeps an independent session.
    let report2 = store_b.import_bundle(bundle).unwrap();
    assert!(report2.reused_blob);
    assert_ne!(report2.session_id, report.session_id);
}

#[test]
fn tampered_bundle_is_rejected() {
    let store_a = temp_store();
    let spec = common::demo_spec();
    store_a.put_protocol("demo").unwrap();
    let version = store_a.save_version("demo", spec.raw.clone(), "v1", None).unwrap();
    let frame = common::legal_demo_frame(&[1], 0);
    let session = store_a
        .create_session("demo", &version.version_hash, &frame, "x")
        .unwrap();
    let mut bundle = store_a.export_session(&session.id).unwrap();

    // Flip a byte in the exported blob without updating the hash: rejected.
    let mut bytes = frame_lab::hex::decode(&bundle.blob_hex).unwrap();
    bytes[1] ^= 0xFF;
    bundle.blob_hex = frame_lab::hex::encode(&bytes);
    let store_b = temp_store();
    assert!(store_b.import_bundle(bundle).is_err());
}

#[test]
fn old_sessions_keep_replaying_against_their_bound_version() {
    let store = temp_store();
    store.put_protocol("evo").unwrap();

    // v1: single-byte payload
    let v1_raw: RawSpec = serde_json::from_value(serde_json::json!({
        "name": "evo", "root": "frame", "endian": "big", "max_depth": 8,
        "structs": [{"name": "frame", "length_field": "total", "fields": [
            {"name": "total", "type": "int", "width": 1},
            {"name": "x", "type": "int", "width": 1}
        ]}]
    }))
    .unwrap();
    let v1 = Spec::compile(v1_raw).unwrap();
    let saved_v1 = store.save_version("evo", v1.raw.clone(), "v1", None).unwrap();

    // v2: adds a field; same frame bytes parse differently under v2.
    let v2_raw: RawSpec = serde_json::from_value(serde_json::json!({
        "name": "evo", "root": "frame", "endian": "big", "max_depth": 8,
        "structs": [{"name": "frame", "length_field": "total", "fields": [
            {"name": "total", "type": "int", "width": 1},
            {"name": "x", "type": "int", "width": 1},
            {"name": "y", "type": "int", "width": 1}
        ]}]
    }))
    .unwrap();
    let v2 = Spec::compile(v2_raw).unwrap();
    let saved_v2 = store.save_version("evo", v2.raw.clone(), "v2", Some(saved_v1.version_hash.clone())).unwrap();
    assert_ne!(saved_v1.version_hash, saved_v2.version_hash);

    // A 2-byte frame is complete under v1, incomplete under v2.
    let bytes = vec![2u8, 0xAB];
    let session = store
        .create_session("evo", &saved_v1.version_hash, &bytes, "bound to v1")
        .unwrap();
    assert_eq!(session.summary.status, frame_lab::parser::Status::Complete);

    // Even after v2 is current, replaying the old session stays v1-consistent.
    let replay = store.replay_session(&session.id).unwrap();
    assert!(replay.consistent);
    assert_eq!(replay.version_hash, saved_v1.version_hash);
    assert_eq!(replay.fresh_summary.status, frame_lab::parser::Status::Complete);
}
