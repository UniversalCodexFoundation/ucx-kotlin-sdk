/*
 * SPDX-License-Identifier: MIT OR Apache-2.0
 *
 * Ucx.kt —— SDK 顶层门面（SDK-API.md §4 的整洁入口）。
 *
 * 暴露与契约一致的顶层操作（命名按 SDK-API §2 Kotlin 本地化为 camelCase）：
 *   - open / openBytes          （§4.1）
 *   - isUcxe                     （§4.6）
 *   - decryptWithKey / decryptWithPassphrase （§4.6）
 *   - capabilities              （§4.7、§7）
 *
 * 这些是模块级（顶层）函数，便于以 `Ucx.open(...)` 风格调用，并在 Java 互操作时
 * 通过 `UcxKt` 静态方法访问。
 */

@file:JvmName("Ucx")

package org.unicodex.ucx

/**
 * 打开 UCX 文件（§4.1）。等价于 [UcxArchive.open]。
 */
fun open(path: String): UcxArchive = UcxArchive.open(path)

/**
 * 从内存字节打开 UCX（§4.1）。等价于 [UcxArchive.openBytes]。
 */
fun openBytes(data: ByteArray): UcxArchive = UcxArchive.openBytes(data)

/**
 * 判断字节序列是否为 UCXE 容器（前 4 字节 == UCXE magic，§4.6）。
 */
fun isUcxe(data: ByteArray): Boolean = UcxeCrypto.isUcxe(data)

/**
 * 直接密钥解密 UCXE（KDF=None；AES-CBC 在此模式被拒，§4.6）。
 * @throws DecryptionException 任何失败（不透明）。
 */
fun decryptWithKey(ucxe: ByteArray, key: ByteArray): ByteArray =
    UcxeCrypto.decryptWithKey(ucxe, key)

/**
 * 口令解密 UCXE（NFC 归一化 → KDF → AEAD/CBC，§4.6）。
 * @throws DecryptionException 任何失败（不透明）。
 */
fun decryptWithPassphrase(ucxe: ByteArray, passphrase: String): ByteArray =
    UcxeCrypto.decryptWithPassphrase(ucxe, passphrase)

/**
 * 返回本 SDK 的能力声明（§4.7、§7）。
 *
 * 本 Kotlin SDK 复用 JVM 生态（JCE + BouncyCastle），达到 L3（全功能）：
 *   - parse / integrity / verifySignatures / decryptDirectKey / decryptPassphrase 全部为 true。
 *   - algorithms：AES-256-GCM、AES-256-CBC、ChaCha20-Poly1305。
 *   - kdfs：argon2id、pbkdf2。
 */
fun capabilities(): Capabilities = Capabilities(
    parse = true,
    integrity = true,
    verifySignatures = true,
    decryptDirectKey = true,
    decryptPassphrase = true,
    algorithms = listOf("AES-256-GCM", "AES-256-CBC", "ChaCha20-Poly1305"),
    kdfs = listOf("argon2id", "pbkdf2"),
)
