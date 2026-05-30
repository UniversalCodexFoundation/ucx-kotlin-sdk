/*
 * SPDX-License-Identifier: MIT OR Apache-2.0
 *
 * Hashing.kt —— BLAKE3 与 Base64 工具（UCX-FORMAT §5、§3.2）。
 *
 * BLAKE3 通过 BouncyCastle 的 Blake3Digest 实现（256-bit 输出 = 32 字节）。
 * Base64 使用 JDK 内置的 standard(padded) 编解码器（RFC 4648 标准字母表 + '=' 填充）。
 */

package org.unicodex.ucx

import org.bouncycastle.crypto.digests.Blake3Digest
import java.util.Base64

/**
 * 哈希与编码工具。
 */
internal object Hashing {

    /** 标准 Base64（带填充）编码器。 */
    private val b64Encoder: Base64.Encoder = Base64.getEncoder()

    /** 标准 Base64（带填充）解码器。 */
    private val b64Decoder: Base64.Decoder = Base64.getDecoder()

    /**
     * 计算输入的 BLAKE3-256 摘要，返回 32 字节原始哈希。
     *
     * BouncyCastle 的 Blake3Digest 构造参数是【输出位数】，传 256 得到 32 字节。
     */
    fun blake3(data: ByteArray): ByteArray {
        // 256-bit = 32-byte 输出，对应 UCX 使用的 BLAKE3-256。
        val digest = Blake3Digest(256)
        digest.update(data, 0, data.size)
        val out = ByteArray(digest.digestSize) // digestSize == 32
        digest.doFinal(out, 0)
        return out
    }

    /**
     * 计算 data 的 BLAKE3 并编码为 standard Base64（带填充）。
     * 这是 MANIFEST.MF 中 digest 的精确编码（UCX-FORMAT §3.2、§5）。
     */
    fun blake3Base64(data: ByteArray): String =
        b64Encoder.encodeToString(blake3(data))

    /** standard Base64（带填充）编码。 */
    fun base64Encode(data: ByteArray): String = b64Encoder.encodeToString(data)

    /** standard Base64（带填充）解码。 */
    fun base64Decode(s: String): ByteArray = b64Decoder.decode(s)
}
