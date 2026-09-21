# 帧解析实验室 (frame-lab)

浏览器里的协议帧解析工作台：上传十六进制字节流 + 小型协议描述，系统把每个字节映射到解析树字段，
支持不可变协议版本、会话回放、字节级编辑重解析、会话包导入导出。

纯 Rust 标准库 HTTP 服务 + 内嵌单页前端，不依赖外部解析服务或系统数据库；
状态全部持久化在仓库目录下的 `frame-lab-data/`。

## 运行

```bash
cargo build --locked          # 交付前安装检查
cargo test --all-targets      # 全部测试（生成数据属性测试 + 存储/API 流程）
cargo run --locked -- --addr 127.0.0.1:5211
# 浏览器打开 http://127.0.0.1:5211 出现「帧解析实验室」
```

可选参数：`--data-dir <目录>`（默认 `./frame-lab-data`）。

## 协议描述（JSON）

```jsonc
{
  "name": "我的协议",
  "root": "frame",          // 根结构名
  "max_depth": 8,           // 递归（payload 展开 / ref）深度上限
  "structs": {
    "frame": [
      { "kind": "int",  "name": "soh", "width": 1, "expect": 165 },
      { "kind": "int",  "name": "length", "width": 2, "endian": "big" },
      // 长度由前面字段决定的有界 payload；内部按 body 结构继续解析
      { "kind": "payload", "name": "payload",
        "len": { "type": "field", "field": "length", "adjust": 0 },
        "struct_ref": "body" },
      // 校验和：覆盖整个父结构，跳过自身字节
      { "kind": "checksum", "name": "crc", "width": 2, "algo": "sum16_be",
        "covers": [], "skip_self": true, "mismatch": "warning" }
    ],
    "body": [
      { "kind": "int", "name": "flags", "width": 1 },
      // 条件子结构：仅当 flags == 1 时出现
      { "kind": "bytes", "name": "ext",
        "len": { "type": "fixed", "len": 2 },
        "when": [{ "field": "flags", "op": "eq", "value": 1 }] }
    ]
  }
}
```

字段种类：`int`（1..=8 字节定长整数，可 `expect` 魔数）、`bytes`（定长/变长字节）、
`payload`（长度由前面字段决定的有界负载，可用 `struct_ref` 展开）、
`struct`（内联子结构）、`ref`（递归引用，受 `max_depth` 限制）、
`checksum`（`sum8` / `sum16_be` / `xor8`，`covers` 指定覆盖字段，`skip_self` 跳过自身）。

## 解析语义

- **complete**：全部字段消费成功；根结构剩余字节记为 `remainder`（警告）。
- **incomplete**：输入尚未完整。诊断给出 `need_more`（仍需字节数下界）与最深字段路径。
- **error**：输入已违反协议（魔数不符、长度越出父结构边界、递归超限、error 级校验和失败）。
  诊断给出最深字段路径与字节偏移。
- 长度字段永远不会把解析带出父结构边界（`length_exceeds_parent`）。
- 校验和在所属结构的兄弟字段全部落位后验证；`skip_self` 时从覆盖区间剔除自身字节。

## 版本与会话

- 协议按规范化 JSON 的 SHA-256 生成**不可变版本**；相同语义内容复用同一版本。
- 会话创建时绑定版本哈希 + blob 哈希，并固化结果快照（状态/诊断/树摘要）。
- 回放永远按创建时绑定的版本重放；新版本不影响旧结论。
- 相同字节样本去重为同一 blob；会话与备注各自独立。
- 导出会话包（JSON）重新导入时校验版本哈希、blob 哈希与重放摘要，全部一致才落盘；
  会话获得新 id，blob 与版本去重。

## JSON API

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/protocols` | 协议与版本列表 |
| POST | `/api/protocols` | 保存协议版本 `{spec}` |
| GET | `/api/versions/{id}` | 版本详情 |
| POST | `/api/parse` | `{version_id, hex}` → 解析结果 |
| POST | `/api/encode` | `{version_id, values}` → 合法帧 hex |
| POST | `/api/blobs` | `{hex}` → blob 哈希（去重） |
| GET | `/api/blobs/{hash}` | 取回字节 |
| GET/POST | `/api/sessions` | 列表 / 创建 `{version_id, hex, note}` |
| GET | `/api/sessions/{id}` | 会话详情 |
| POST | `/api/sessions/{id}/note` | 更新备注 |
| POST | `/api/replay` | `{session_id}` → 按绑定版本重放 |
| POST | `/api/export` | `{session_id}` → 会话包 |
| POST | `/api/import` | `{bundle}` → 导入会话包 |

## 存储布局（`frame-lab-data/`）

```
index.json            # 协议/版本/会话索引
versions/<id>.json    # 不可变协议版本
blobs/<hh>/<hash>.bin # 内容寻址字节流
sessions/<id>.json    # 会话记录 + 结果快照
```

## 测试

`tests/frame_contract.rs`：生成合法帧必解析成功、截断只产生 incomplete（含下界）、
单字节破坏稳定落点、恶意长度不越界、递归上限、校验和自排除、重算差异。
`tests/store_flow.rs`：版本不可变与去重、blob 去重、会话独立备注、旧会话按绑定版本回放、
导出导入确定性、篡改拒绝。`tests/api_flow.rs`：HTTP API 全生命周期与随机输入解析确定性。
