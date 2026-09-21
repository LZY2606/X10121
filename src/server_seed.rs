use crate::store::Store;

/// 首次启动时写入内置演示协议版本与一条合法样本会话。
pub fn seed(store: &Store) -> crate::error::LabResult<()> {
    let protocols = store.list_protocols()?;
    if !protocols.is_empty() {
        return Ok(());
    }
    let protocol = crate::demo::protocol();
    let version = store.save_version(&protocol)?;
    let bytes = crate::encoder::encode(&protocol, &crate::demo::sample_values())?;
    store.create_session(
        &version.version_id,
        &bytes,
        "内置演示：合法帧（编码后再解析）",
    )?;
    Ok(())
}
