# Unicodex UCX SDK — Kotlin / JVM

> 统一标准小说文件格式 `.ucx` 的 **只读阅读器** SDK（Kotlin / JVM 实现）。
> 提供：解析(parse) + 完整性校验(integrity, BLAKE3) + 双层签名验证(verify, Ed25519) + UCXE 解密(decrypt)。
> **不含** 写入 / 签名 / 加密。

本 SDK 遵循 [`sdk/UCX-FORMAT.md`](../UCX-FORMAT.md)（字节级 wire-format）与 [`sdk/SDK-API.md`](../SDK-API.md)（跨语言统一 API 契约）。

- 包 / 命名空间：`org.unicodex.ucx`
- 许可证：**MIT OR Apache-2.0**
- 能力等级：**L3（全功能）**

---

## 安装

本 SDK 使用 Gradle（Kotlin DSL）构建，依赖 JVM 生态：

| 用途 | 依赖 |
|------|------|
| ZIP 容器读取 | `java.util.zip`（JDK 内置） |
| JSON 解析 | `org.jetbrains.kotlinx:kotlinx-serialization-json` |
| BLAKE3 / Ed25519 / Argon2id / ChaCha20-Poly1305 / X.509 | `org.bouncycastle:bcprov-jdk18on`、`bcpkix-jdk18on` |
| AES-GCM / AES-CBC / HMAC-SHA256 / PBKDF2 | JCE（JDK 内置） |

在你的 `build.gradle.kts` 中引入（发布后）：

```kotlin
dependencies {
    implementation("org.unicodex.ucx:unicodex-ucx:0.4.0")
}
```

要求 JDK 17+（开发与测试在 JDK 21 上完成）。

---

## 用法示例

```kotlin
import org.unicodex.ucx.*

// 1) 打开归档（校验 ZIP magic@0 + mimetype，并解析 codex/struct/manifest）
val archive = UcxArchive.open("sample.ucx")
// 或从内存字节：UcxArchive.openBytes(bytes)

// 2) 元数据与目录
println(archive.codex.title.main)          // "Sample Novel"
println(archive.codex.language)            // "en"
for (ch in archive.chapters()) {
    println("${ch.title} -> ${ch.path}")    // "第一章 -> content/chapter-001.md"
}

// 3) 读取章节（明文）
val text = archive.readChapterText("chapter-001.md")

// 4) 完整性校验（BLAKE3 vs MANIFEST，Base64 比对）
val integrity = archive.verifyIntegrity()
println(integrity.valid)                    // true

// 5) 签名验证（Layer1 SF/EC + Layer2 签名块，均为 Ed25519）
val sig = UcxArchive.open("sample-signed.ucx").verifySignatures()
println(sig.status)                         // VERIFIED
println(sig.signers.first().fingerprint)    // c7eda2f7...

// 6) 解密 UCXE（模块级函数）
val key = java.util.Base64.getDecoder()
    .decode("MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=")     // 32 字节
val plain1 = decryptWithKey(File("plain-aesgcm.ucxe").readBytes(), key)
val plain2 = decryptWithPassphrase(File("plain-pass.ucxe").readBytes(), "sdktest-passphrase")

// 7) 能力查询
println(capabilities())
```

UCXE 检测：

```kotlin
if (isUcxe(bytes)) { /* 这是加密章节 */ }
// 或：archive.isChapterEncrypted("chapter-001.md")
```

---

## 能力矩阵（`capabilities()`）

| 能力 | 状态 | 说明 |
|------|------|------|
| `parse` | ✅ true | ZIP + JSON + 容器校验 |
| `integrity` | ✅ true | BLAKE3（BouncyCastle `Blake3Digest`） |
| `verifySignatures` | ✅ true | Ed25519 双层（Layer1 SF/EC + Layer2 签名块） |
| `decryptDirectKey` | ✅ true | KDF=None；GCM / ChaCha20 |
| `decryptPassphrase` | ✅ true | NFC → KDF → AEAD/CBC |
| `algorithms` | `AES-256-GCM`, `AES-256-CBC`, `ChaCha20-Poly1305` | GCM/CBC 用 JCE；ChaCha20-Poly1305 用 BouncyCastle |
| `kdfs` | `argon2id`, `pbkdf2` | Argon2id 用 BouncyCastle；PBKDF2-HMAC-SHA256 用 JCE |

本 SDK 达到 **L3（全功能）**。

---

## 量化常量

所有 SDK-API.md §6 常量通过 `UcxConstants` 暴露，例如：

```kotlin
UcxConstants.MIMETYPE                 // "application/vnd.unicodex+zip"
UcxConstants.UCXE_MAGIC              // [0x55,0x43,0x58,0x45]
UcxConstants.ALGO_AES_256_GCM       // 0x01
UcxConstants.ARGON2_DEFAULT_MEM_KIB // 65536
UcxConstants.L2_BLOCK_MAGIC         // "UCX Sig Block 1\0"
```

---

## 错误模型

公开 API 失败时抛出 `UcxException` 的子类（SDK-API.md §5）：

| 异常 | 触发 |
|------|------|
| `InvalidFormatException` | 非 ZIP、mimetype 不符、UCX MAJOR>1、UCXE magic/version 非法 |
| `NotFoundException` | 请求的条目 / 章节不存在 |
| `ParseException` | JSON / MANIFEST 解析失败 |
| `UnsupportedException` | 未实现的算法 / KDF / 能力 |
| `DecryptionException` | 任何解密失败（**不透明**：统一文案、不携带 cause，防 oracle） |
| `UcxIoException` | 文件读写失败 |

---

## 测试

一致性测试 T1–T10（SDK-API.md §8）位于 `src/test/kotlin/`，断言取自 `testdata/expected.json`。

```bash
gradle test
```

夹具自包含于 `testdata/`（同时复制到 `src/test/resources/testdata/` 供测试 classpath 加载），便于独立开源。

---

## Limitations（已知限制）

- **仅只读**：不实现写入 / 签名 / 加密（符合任务范围）。
- **仅 Ed25519 签名**：与参考实现一致，RSA/ECDSA 未实现（格式也未使用）。
- **分块解密路径** 已实现（§7.7），但夹具均为小文件（< 64 MiB），分块路径未被一致性夹具覆盖，仅靠代码逻辑保证正确（base[0..8]‖u32_be(idx) 子 nonce、逐块 tag、文件级 AAD）。
- **X.509 信任策略**：与参考验证器一致，仅读取 SPKI 公钥与 validity 窗口，不做 CA 链 / 路径校验；信任策略交由应用层。
- **PBKDF2 口令字节**：JDK 的 `PBKDF2WithHmacSHA256` 以 UTF-8 编码字符；本 SDK 对口令先做 NFC 归一化再派生，与参考实现一致。当前一致性夹具仅覆盖 Argon2id 口令模式，PBKDF2 路径未被夹具覆盖。

---

## 设计取舍

- BLAKE3 与 Argon2id 通过 **BouncyCastle 轻量级 API** 直接调用（`Blake3Digest` / `Argon2BytesGenerator`），无需注册 JCE Provider。
- ChaCha20-Poly1305 使用 BouncyCastle `ChaCha20Poly1305` 引擎（JDK 11 起 JCE 虽有 ChaCha20-Poly1305，但为统一 AAD 处理与跨 JDK 行为，选用 BC 引擎）。
- AES-GCM / AES-CBC / HMAC-SHA256 / PBKDF2 使用 **JCE**（JDK 内置），性能与可用性最佳。
- Layer 2 签名块定位与受保护内容重构直接操作 **原始磁盘字节**（`ZipReader.rawBytes`），其余解析 / 完整性 / 解密均作用于 **解压后字节**。

---

## 版本号说明 (Versioning)

本 SDK 采用 `X.Y.Z` 版本号（见项目 ADR-012）：
- **`X.Y`**（前两位）= 所支持的 **UCX 标准版本**（major.minor）。**前两位相同 ⇒ 支持同一 UCX 标准、对外 API 相同**。
- **`Z`**（末位）= 本 SDK 自身的补丁号（修 bug、不改对外 API）。

当前版本 **0.4.0** 对应 UCX 标准 **0.4.x**。当 UCX 标准升级到下一个 minor（如 0.5）时会有新的 SDK 线（0.5.x），
而旧标准线（0.4.x）**持续发布补丁、不被废弃**（类似 Python 对多个版本系列并行维护）。
