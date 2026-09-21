# 帧解析实验室 (Frame Parsing Laboratory)

一个纯 Rust 实现、运行在浏览器里的二进制帧解析实验室。使用者上传十六进制字节流和一份
小型 JSON 协议描述，系统把每个字节映射到解析树字段，支持字节高亮联动、字节编辑后重新解
析、不可变协议版本以及可回看的诊断会话。

- 无外部解析服务、无系统数据库：状态以 JSON/原始字节持久化在仓库目录中。
- 仅依赖 `serde` / `serde_json`；HTTP 服务和 SHA-256 均为标准库实现。

## 构建与演示

```bash
cargo build --locked
cargo test --all-targets
cargo run --locked -- --addr 127.0.0.1:5211
```

浏览器打开 <http://127.0.0.1:5211>，页面标题为“帧解析实验室”。
可选参数：`--data-dir <目录>`（默认 `frame-lab-data/`）。

## 协议描述

协议是一份 JSON，保存版本时按字段名排序做规范化哈希（SHA-256），得到不可变版本号。
示例：

```json
{
  "name": "demo",
  "root": "frame",
  "endian": "big",
  "max_depth": 8,
  "structs": [
    {
      "name": "frame",
      "length_field": "total",
      "fields": [
        {"name": "total", "type": "int", "width": 1},
        {"name": "magic", "type": "int", "width": 2, "expect": 61377},
        {"name": "payload_len", "type": "int", "width": 1},
        {"name": "payload", "type": "bytes", "length": {"field": "payload_len"}},
        {"name": "crc", "type": "checksum", "algo": "xor8",
         "cover": [{"from": "magic", "to": {"field": "payload", "edge": "end"}}]}
      ]
    }
  ]
}
```

支持的字段类型：

- `int`：定宽 1..=8 字节整数，`expect` 常量、`signed`、`endian` 覆盖。
- `bytes`：变长字节，`length` 引用前置整数，或 `rest: true` 取到父边界。
- `cstring`：NUL 结尾字符串，可选 `max_len`。
- `struct`：嵌套子结构；子结构可有自己的 `length_field`。
- `array`：`count` 为常量或前置整数，`item` 声明元素类型。
- `checksum`：`sum8`/`xor8`，`cover` 区间端点可引用同层字段或绝对偏移；
  校验和自身字节始终从覆盖区间排除（自排除）。

结构可用 `length_field` 声明自身总长度（必须是首个字段）；长度字段不能把解析带出父边
界。字段可用 `when` 条件（`eq` / `flag` / `fields_eq`）声明。递归结构由 `max_depth`
限制，编译器拒绝静态无限递归环。

## 三种解析结果

- `complete`：所有字段解析成功（可能附带尾部字节等警告）。
- `incomplete`：输入是某帧的合法前缀，给出仍需字节数的下界、最深字段路径和偏移。
- `error`：输入违反协议，给出最深字段路径和字节偏移（常量不符、越界、校验和错、深度超限）。

## 版本与会话

- 保存版本即不可变；会话永久绑定创建时的版本，新版本不会改变旧结论。
- 相同样本字节内容定址（SHA-256）到同一个 blob，但会话与备注各自独立。
- 会话可导出为单个 JSON 包；导入时校验版本哈希、blob 哈希并重放解析，
  保证版本、字节、诊断和解析树摘要完全一致且确定。

## JSON API

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/api/health` | 健康检查 |
| GET/POST | `/api/protocols` | 列出/新建协议 |
| GET | `/api/protocols/{name}/versions` | 版本历史 |
| POST | `/api/validate` | 校验协议 JSON（不保存） |
| POST | `/api/versions` | 保存不可变版本 |
| GET | `/api/versions/{hash}[/raw]` | 取版本（/raw 取可编辑 JSON） |
| POST | `/api/parse` | 用版本哈希或内联 spec 解析 `hex`/`bytes` |
| POST | `/api/blobs` · GET `/api/blobs/{hash}` | 字节样本定址存取 |
| POST/GET | `/api/sessions` · GET `/api/sessions/{id}` | 保存/列出/读取会话 |
| PATCH | `/api/sessions/{id}/note` | 更新备注 |
| GET | `/api/sessions/{id}/replay` | 按绑定版本重放 |
| GET | `/api/sessions/{id}/export` · POST `/api/import` | 导出/导入会话包 |

## 测试

基于编码器生成的合法帧做数据驱动测试，覆盖：

- 合法帧完整解析、逐字节映射；
- 任意严格截断只产生 `incomplete` 且下界正确；
- 单字节破坏稳定落到相同字段路径；
- 恶意长度字段越界、总长度小于头部；
- 递归深度上限与静态递归环拒绝；
- 校验和覆盖区间自排除（`xor8`/`sum8`）；
- blob 去重、版本绑定、会话独立性与导出/导入的确定性。

```bash
cargo test --all-targets
```
