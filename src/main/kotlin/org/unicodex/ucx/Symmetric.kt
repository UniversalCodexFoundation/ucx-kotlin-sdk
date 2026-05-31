/*
 * SPDX-License-Identifier: MIT OR Apache-2.0
 *
 * Symmetric.kt —— 对称解密原语（UCX-FORMAT §7.5、§7.6、§7.7、§7.9）。
 *
 * 实现：
 *   - AES-256-GCM：JCE "AES/GCM/NoPadding"（tag 16）。
 *   - ChaCha20-Poly1305：BouncyCastle ChaCha20Poly1305 引擎（tag 16）。
 *   - AES-256-CBC + HMAC-SHA256（Encrypt-then-MAC）：先验 HMAC，再 AES-CBC 解密 + PKCS#7 去填充。
 *   - 分块 AEAD（§7.7）：仅 GCM/ChaCha20；逐块解密后拼接。
 *
 * 所有失败抛异常（由 UcxeCrypto.runOpaque 折叠为不透明 DecryptionException）。
 */

package org.unicodex.ucx

import org.bouncycastle.crypto.modes.ChaCha20Poly1305
import org.bouncycastle.crypto.params.AEADParameters
import org.bouncycastle.crypto.params.KeyParameter
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

internal object Symmetric {

    // =================================================================================
    // 非分块 AEAD（GCM / ChaCha20，§7.9）
    // =================================================================================

    /**
     * 解密非分块 AEAD：require 12-byte nonce + 16-byte tag；AAD = aeadAad()（§7.6）。
     */
    fun decryptAead(header: UcxeHeader, key: ByteArray): ByteArray {
        if (header.iv.size != UcxConstants.AEAD_NONCE_LEN) {
            throw IllegalStateException("AEAD nonce must be 12 bytes")
        }
        if (header.tag.size != 16) {
            throw IllegalStateException("AEAD tag must be 16 bytes")
        }
        val aad = header.aeadAad()
        return when (header.algoId) {
            UcxConstants.ALGO_AES_256_GCM ->
                aesGcmDecrypt(key, header.iv, header.ciphertext, header.tag, aad)
            UcxConstants.ALGO_CHACHA20_POLY1305 ->
                chacha20Poly1305Decrypt(key, header.iv, header.ciphertext, header.tag, aad)
            else -> throw IllegalStateException("not an AEAD algorithm")
        }
    }

    /**
     * AES-256-GCM 解密。JCE 的 GCM 期望 ciphertext‖tag 拼接，故先拼回再解。
     */
    private fun aesGcmDecrypt(
        key: ByteArray, nonce: ByteArray, ciphertext: ByteArray, tag: ByteArray, aad: ByteArray,
    ): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val spec = GCMParameterSpec(UcxConstants.GCM_TAG_LEN * 8, nonce)
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), spec)
        cipher.updateAAD(aad)
        // JCE GCM 解密的输入是 ciphertext ‖ tag。
        val combined = ciphertext + tag
        return cipher.doFinal(combined) // tag 不匹配抛 AEADBadTagException
    }

    /**
     * ChaCha20-Poly1305 解密（BouncyCastle 引擎）。
     * BC 的 processBytes/doFinal 对解密同样期望 ciphertext‖tag 拼接输入。
     */
    private fun chacha20Poly1305Decrypt(
        key: ByteArray, nonce: ByteArray, ciphertext: ByteArray, tag: ByteArray, aad: ByteArray,
    ): ByteArray {
        val engine = ChaCha20Poly1305()
        // macSize 以 bit 计：128 bit = 16 byte。
        val params = AEADParameters(KeyParameter(key), 128, nonce, aad)
        engine.init(false, params) // false = 解密
        val input = ciphertext + tag
        val out = ByteArray(engine.getOutputSize(input.size))
        var len = engine.processBytes(input, 0, input.size, out, 0)
        len += engine.doFinal(out, len) // tag 不匹配抛 InvalidCipherTextException
        return if (len == out.size) out else out.copyOf(len)
    }

    // =================================================================================
    // 分块 AEAD（§7.7）
    // =================================================================================

    /**
     * 解密分块 AEAD（仅 GCM/ChaCha20）。
     *
     * header.iv = 12 字节 base nonce；header.ciphertext = 序列化 chunk 流：
     *   [chunk_count:u32 LE] 后跟 chunk_count 个 [size:u32 LE][ct][tag:16]。
     * 每块 nonce = base[0..8] ‖ u32_be(index)；
     * AAD = file_aad ‖ u32_le(chunk_count)（anti-truncation，§7.6/§7.7）。
     *
     * chunk_count 被追加到 AAD 中，以防止截断攻击：攻击者无法在不破坏 AEAD 认证
     * 的情况下修改分块总数。参考 Rust ucx-crypto/src/chunked.rs:135-140 build_chunk_aad()。
     */
    fun decryptChunkedAead(header: UcxeHeader, key: ByteArray): ByteArray {
        if (header.iv.size != UcxConstants.AEAD_NONCE_LEN) {
            throw IllegalStateException("chunked base nonce must be 12 bytes")
        }
        val fileAad = header.aeadAad()
        val cur = ByteCursor(header.ciphertext)
        val chunkCount = cur.u32le()
        // 分块数上界校验：防止恶意输入导致 DoS（硬上限 16M 块 = 16 TiB @ 1 MiB/chunk）。
        if (chunkCount < 0 || chunkCount > UcxConstants.MAX_CHUNK_COUNT) {
            throw IllegalStateException("invalid chunk count")
        }
        // (anti-truncation) chunk_aad = file_aad || u32_le(chunk_count)
        // 将 chunk_count 的 4 字节小端表示追加到文件级 AAD，使 AEAD 认证绑定总分块数。
        val chunkAad = fileAad + ByteIO.u32leBytes(chunkCount)
        val baseHi = header.iv.copyOfRange(0, 8) // 前 8 字节
        val out = java.io.ByteArrayOutputStream()
        for (i in 0 until chunkCount) {
            val ctSize = cur.u32le()
            if (ctSize < 0 || ctSize > UcxConstants.MAX_CIPHERTEXT_LEN) {
                throw IllegalStateException("invalid chunk ct size")
            }
            val ct = cur.bytes(ctSize.toInt())
            val tag = cur.bytes(16)
            // 子 nonce = base[0..8] ‖ u32_be(index)
            val nonce = baseHi + ByteIO.u32beBytes(i)
            val plain = when (header.algoId) {
                UcxConstants.ALGO_AES_256_GCM -> aesGcmDecrypt(key, nonce, ct, tag, chunkAad)
                UcxConstants.ALGO_CHACHA20_POLY1305 ->
                    chacha20Poly1305Decrypt(key, nonce, ct, tag, chunkAad)
                else -> throw IllegalStateException("chunked supports AEAD only")
            }
            out.write(plain)
        }
        return out.toByteArray()
    }

    // =================================================================================
    // AES-256-CBC + HMAC-SHA256（Encrypt-then-MAC，§7.9）
    // =================================================================================

    /**
     * 解密 AES-256-CBC：
     *   1) 先验 HMAC-SHA256 over (header(8) ‖ iv ‖ ciphertext)，常量时间比较（§7.6、§7.9）。
     *   2) 再 AES-CBC 解密 + PKCS#7 去填充。
     *
     * @param encKey 32 字节加密密钥。
     * @param macKey 32 字节 MAC 密钥。
     */
    fun decryptCbc(header: UcxeHeader, encKey: ByteArray, macKey: ByteArray): ByteArray {
        if (header.iv.size != UcxConstants.CBC_IV_LEN) {
            throw IllegalStateException("CBC IV must be 16 bytes")
        }
        if (header.tag.size != UcxConstants.CBC_MAC_LEN) {
            throw IllegalStateException("CBC HMAC tag must be 32 bytes")
        }
        // 1) HMAC 校验：覆盖 aad(8) ‖ iv ‖ ciphertext。
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(macKey, "HmacSHA256"))
        mac.update(header.cbcAad())   // header(8) only
        mac.update(header.iv)
        mac.update(header.ciphertext)
        val computed = mac.doFinal()
        if (!constantTimeEquals(computed, header.tag)) {
            throw IllegalStateException("CBC HMAC mismatch")
        }
        // 2) AES-CBC 解密 + PKCS#7 去填充（JCE 的 PKCS5Padding 等价于 16 字节块的 PKCS#7）。
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(
            Cipher.DECRYPT_MODE,
            SecretKeySpec(encKey, "AES"),
            IvParameterSpec(header.iv),
        )
        return cipher.doFinal(header.ciphertext)
    }

    /**
     * 常量时间字节数组比较，避免时间侧信道。
     *
     * 即使长度不同也必须迭代较短长度的全部字节，避免因提前返回泄露长度信息。
     * 长度不等时 diff 预设为非零，但仍完成遍历以保持常量时间特性。
     * 参考 Rust 参考实现：使用 subtle::ConstantTimeEq，不因长度差异提前返回。
     */
    private fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean =
        CryptoUtil.constantTimeEquals(a, b)
}

/**
 * 密码学工具函数，供多个模块共享（Symmetric / SignatureVerifier / UcxArchive）。
 */
internal object CryptoUtil {

    /**
     * 常量时间字节数组比较，避免时间侧信道泄露。
     *
     * 长度不等时 diff 预设为非零，但仍完成遍历以保持常量时间特性。
     */
    fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean {
        var diff = a.size xor b.size
        val minLen = minOf(a.size, b.size)
        for (i in 0 until minLen) {
            diff = diff or (a[i].toInt() xor b[i].toInt())
        }
        return diff == 0
    }

    /**
     * 常量时间字符串比较，避免时间侧信道泄露。
     *
     * 将两个字符串转为 UTF-8 字节后使用常量时间字节比较。
     * 用于 BLAKE3 摘要的 Base64 字符串比对等场景。
     */
    fun constantTimeEquals(a: String, b: String): Boolean =
        constantTimeEquals(a.toByteArray(Charsets.UTF_8), b.toByteArray(Charsets.UTF_8))
}
