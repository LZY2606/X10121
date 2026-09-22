# 帧解析实验室（Frame Parsing Lab）

一个完全在本地运行、**零外部依赖**（仅 Rust 标准库，无外部解析服务、无系统数据库）
的浏览器帧解析实验室。上传十六进制字节流和一份小型协议描述，系统会把每个字节
映射到解析树中的字段，支持树节点 ↔ 字节双向高亮、改字节后重新解析、会话回看，
以及不可变的协议版本管理。

## 运行

```bash
cargo test --all-targets
cargo run --locked -- --addr 127.0.0.1:5211
# 浏览器打开 http://127.0.0.1:5211 ，页面标题为“帧解析实验室”
```

可选参数：`--data-dir <目录>`（默认 `./frame_lab_data`，仓库目录持久化）。

交付前安装检查：`cargo build --locked`。

## 协议描述（JSON）

```jsonc
{
  "name": "演示设备帧 DemoFrame v1",
  "root": "frame",
  "max_depth": 8,                 // 递归结构可配置深度上限
  "structs": [
    {
      "name": "frame",
      "length_ref": { "field": "frame_len" }, // 整个结构的硬边界来自前置字段
      "fields": [
        { "name": "soi", "type": "u8", "const": 170 },        // 定长整数/常量
        { "name": "frame_len", "type": "u16", "endian": "be",
          "enum": [{ "value": 19, "label": "数据帧" }] },     // 枚举（未知值告警）
        { "name": "kind", "type": "u8" },
        { "name": "seq", "type": "u16", "endian": "le" },     // 支持字节序/有符号
        { "name": "body", "type": "struct", "struct": "body" },
        { "name": "chk", "type": "u8",
          "checksum": { "algo": "sum8",                       // sum8 / xor8
                         "covers": ["soi", "@end"],           // 覆盖区间标记
                         "skip_self": true } }                // 跳过自身字段
      ]
    },
    {
      "name": "body",
      "length_ref": { "field": "clen" },
      "fields": [
        { "name": "clen", "type": "u16", "endian": "be" },
        { "name": "payload", "type": "bytes", "length": 3 },  // 定长
        { "name": "tail", "type": "struct", "struct": "tail",
          "when": { "field": "kind", "eq": 2 } },             // 条件子结构
        { "name": "node", "type": "struct", "struct": "node" }
      ]
    },
    { "name": "tail", "fields": [{ "name": "marker", "type": "u8", "const": 205 }] },
    { "name": "node", "fields": [
        { "name": "ntype", "type": "u8" },
        { "name": "nlen",  "type": "u8" },
        { "name": "nval",  "type": "bytes", "length": "nlen" }, // 由前置字段决定长度
        { "name": "child", "type": "struct", "struct": "node",
          "when": { "field": "ntype", "eq": 1 } }               // 递归子结构
    ]}
  ]
}
```

长度表达式支持：数字（定长）、`"字段名"`、`{ "field": "字段名", "offset": -2 }`。
校验和覆盖标记支持字段名（取该字段起点）以及 `@start` / `@end`。

## 解析语义

- **严格区分两种未成功状态**
  - `incomplete`：输入尚未完整。报告**仍需字节数下界**（`need`，正整数）与最深字段路径。
  - `violation`：输入已违反协议。报告错误码、**最深字段路径**与**字节偏移**。
- **父结构边界**：任何字段（含由长度字段决定的 payload）都不能把解析带出父结构
  的硬边界，越界直接 `length_out_of_bounds` / `field_out_of_bounds`，绝不越界读。
- **递归深度**：结构嵌套层数受 `max_depth` 约束，超出报 `max_depth`。
- **校验和**：结构闭合后按覆盖区间评估，`skip_self` 时跳过校验字段自身。
- 其它告警：枚举未知值（`enum_unknown`）、根结构后有多余字节（`trailing_bytes`）等。
- 任意合法帧的**每个真前缀**都只会得到 `incomplete`（测试强制保证）。

## 版本、会话与导入导出

- 协议保存为**不可变版本**；相同内容幂等返回原版本号。
- 会话绑定创建/修订时的协议版本；**历史会话永远按绑定版本重放**，新版本不会
  改变旧结论（会话保存 `tree_digest` 与完整 `report_digest`，回看时校验一致性）。
- 样本按 SHA-256 **内容寻址**：相同样本指向已有 blob；会话与备注各自独立。
- 导出为确定性 JSON 包；重新导入后协议版本（按摘要去重）、字节、诊断与解析树摘要
  保持一致，导入会实际重放并逐修订校验。

## JSON API（与浏览器能力等价）

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/api/demo` | 内置演示协议与编码器生成的合法样本 |
| GET/POST | `/api/protocols` | 列出 / 新建协议 |
| GET | `/api/protocols/{id}` | 协议与全部不可变版本 |
| POST | `/api/protocols/{id}/versions` | 保存新版本（内容相同则幂等） |
| POST | `/api/parse` | 用 `spec` 或 `protocol_id`+`version` 解析 `hex` |
| POST/GET | `/api/blobs`、`/api/blobs/{sha256}` | 内容寻址样本存取 |
| GET/POST | `/api/sessions` | 会话列表 / 创建 |
| GET/PATCH | `/api/sessions/{id}` | 回看（含重放校验）/ 改标题备注 |
| POST | `/api/sessions/{id}/revisions` | 字节改后追加修订（版本不变） |
| POST | `/api/sessions/{id}/export` | 导出确定性会话包 |
| POST | `/api/import` | 导入会话包并重放校验 |

## 代码结构

- `src/json.rs`、`src/hash.rs`、`src/hexutil.rs`：零依赖 JSON / SHA-256 / hex
- `src/spec.rs`：协议描述模型与校验
- `src/parser.rs`：解析器（字节→解析树、incomplete/violation、边界/递归/校验和）
- `src/encoder.rs`：对称编码器（自动算校验和），测试用它生成合法帧
- `src/storage.rs`：仓库持久化、blob、不可变版本、会话、导入导出
- `src/api.rs`、`src/server.rs`：JSON API 与零依赖 HTTP 服务
- `src/static/`：内嵌中文单页前端
- `tests/`：生成数据驱动测试（见下）

## 测试（生成数据驱动）

- `roundtrip`：编码器生成的合法帧解析成功；**所有真前缀只产生 incomplete**；随机 payload 批量闭环
- `corruption`：单字节破坏重复解析得到**完全一致**结论；破坏位置稳定落到语义对应字段路径
- `malicious_length`：恶意长度不能越过父结构边界；越界报错偏移不超过输入长度
- `recursion`：递归深度上限可配置，超限稳定落到 `child` 路径
- `checksum`：sum8/xor8 的自排除语义；覆盖区间被截断时是 incomplete
- `storage_io`：blob 去重、会话/备注独立、导入导出确定性、新版本不改变历史会话
- `api`：JSON API 等价、字节修改后摘要变化且版本绑定不变
