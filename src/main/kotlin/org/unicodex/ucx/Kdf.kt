/*
 * SPDX-License-Identifier: MIT OR Apache-2.0
 *
 * Kdf.kt —— 口令密钥派生（UCX-FORMAT §8）。
 *
 * 支持两种 KDF：
 *   - Argon2id（KDF id 0x01）：BouncyCastle Argon2BytesGenerator，version 0x13（v19）。
 *   - PBKDF2-HMAC-SHA256（KDF id 0x02）：JDK 内置 SecretKeyFactory。
 *
 * 关键约束（§7.8、§8.3）：
 *   - 口令先做 Unicode NFC 归一化，再以 UTF-8 字节进入 KDF。
 *   - salt 必须恰好 16 字节（解密路径）。
 *   - 输出长度：AEAD 32 字节；AES-CBC 64 字节（enc=derived[0..32]，mac=derived[32..64]）。
 *   - 参数必须在解密前校验，超界即拒绝（这里抛 IllegalArgumentException，由上层折叠为 DecryptionException）。
 */

package org.unicodex.ucx

import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters
import java.text.Normalizer

/** 解析出的 KDF 描述（id + 参数）。 */
internal sealed class KdfSpec {
    /** 直接密钥模式（无 KDF）。 */
    object None : KdfSpec()

    /** Argon2id（§8.1）。 */
    data class Argon2id(val memoryKib: Long, val timeCost: Long, val parallelism: Long) : KdfSpec()

    /** PBKDF2-HMAC-SHA256（§8.2）。 */
    data class Pbkdf2(val iterations: Long) : KdfSpec()
}

/**
 * KDF 实现。
 */
internal object Kdf {

    /**
     * 校验 KDF 参数是否在允许范围内（§8.1、§8.2）。超界抛 IllegalArgumentException。
     * 必须在尝试解密【之前】调用（对齐 validate_kdf_params）。
     */
    fun validate(spec: KdfSpec) {
        when (spec) {
            is KdfSpec.None -> {}
            is KdfSpec.Argon2id -> {
                require(
                    spec.memoryKib in UcxConstants.ARGON2_MIN_MEM_KIB..UcxConstants.ARGON2_MAX_MEM_KIB
                ) { "argon2 memory out of range" }
                require(
                    spec.timeCost in UcxConstants.ARGON2_MIN_TIME..UcxConstants.ARGON2_MAX_TIME
                ) { "argon2 time out of range" }
                require(
                    spec.parallelism >= UcxConstants.ARGON2_MIN_PARALLELISM
                ) { "argon2 parallelism out of range" }
            }
            is KdfSpec.Pbkdf2 -> {
                require(
                    spec.iterations in UcxConstants.PBKDF2_MIN_ITERS..UcxConstants.PBKDF2_MAX_ITERS
                ) { "pbkdf2 iterations out of range" }
            }
        }
    }

    /**
     * 由口令 + salt + KDF 参数派生 outLen 字节的密钥。
     *
     * @param passphrase 明文口令（将被 NFC 归一化）。
     * @param salt       盐（必须恰好 16 字节，调用方负责校验）。
     * @param outLen     输出长度（AEAD=32，CBC=64）。
     */
    fun derive(spec: KdfSpec, passphrase: String, salt: ByteArray, outLen: Int): ByteArray {
        require(passphrase.isNotEmpty()) { "empty passphrase rejected" }
        // (§7.8) 口令先做 Unicode NFC 归一化，再取 UTF-8 字节。
        val normalized = Normalizer.normalize(passphrase, Normalizer.Form.NFC)
        val pwBytes = normalized.toByteArray(Charsets.UTF_8)

        try {
        return when (spec) {
            is KdfSpec.None ->
                throw IllegalArgumentException("KDF=None has no passphrase derivation")

            is KdfSpec.Argon2id -> {
                val params = Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                    .withVersion(UcxConstants.ARGON2_VERSION) // 0x13 (v19)
                    .withMemoryAsKB(spec.memoryKib.toInt())
                    .withIterations(spec.timeCost.toInt())
                    .withParallelism(spec.parallelism.toInt())
                    .withSalt(salt)
                    .build()
                val gen = Argon2BytesGenerator()
                gen.init(params)
                val out = ByteArray(outLen)
                gen.generateBytes(pwBytes, out)
                out
            }

            is KdfSpec.Pbkdf2 -> {
                // (P0 critical fix) JDK 的 PBKDF2WithHmacSHA256 将 char[] 按 ISO-8859-1
                // 风格取每个字符的低 8 位作为字节，与参考实现要求的 UTF-8 编码不一致。
                // 对于非 ASCII 密码短语（中文、日文、emoji 等），JDK 会产生错误的密钥，
                // 导致无法解密其他 SDK 加密的文件。
                //
                // 改用 BouncyCastle 的 PKCS5S2ParametersGenerator 直接传入 UTF-8 字节，
                // 与 Java SDK 的 bcPbkdf2() 方法完全一致。
                // 参考：Java SDK Kdf.java bcPbkdf2() 方法。
                val gen = org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator(
                    org.bouncycastle.crypto.digests.SHA256Digest()
                )
                gen.init(pwBytes, salt, spec.iterations.toInt())
                val kp = gen.generateDerivedParameters(outLen * 8)
                        as org.bouncycastle.crypto.params.KeyParameter
                kp.key
            }
        }
        } finally {
            // (P1 安全) best-effort 清零口令字节，减少敏感数据在内存中的驻留时间。
            pwBytes.fill(0)
        }
    }
}
