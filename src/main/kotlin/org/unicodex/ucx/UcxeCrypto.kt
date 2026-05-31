/*
 * SPDX-License-Identifier: MIT OR Apache-2.0
 *
 * UcxeCrypto.kt —— UCXE 解密（UCX-FORMAT §7、§8）。
 *
 * 公开模块级操作（SDK-API §4.6）：
 *   - isUcxe(bytes): 前 4 字节是否 == UCXE magic。
 *   - decryptWithKey(ucxe, key32): KDF=None 直接密钥；AES-CBC 在此模式被拒。
 *   - decryptWithPassphrase(ucxe, passphrase): 口令模式（NFC→KDF→AEAD/CBC）。
 *
 * 头部字段序（§7.2）：
 *   magic(4)|ver(1)|algo(1)|kdf(1)|flags(1)|KDF参数(0/4/12)|saltLen(u16)|salt|
 *   ivLen(u16)|iv|ctLen(u64)|ciphertext|tag。整数 LE。
 *
 * AAD（§7.6）：
 *   - AEAD(GCM/ChaCha20): header(8) ‖ kdf_params ‖ salt（用磁盘上的原始 flags 字节）。
 *   - AES-CBC 的 HMAC 覆盖 header(8) ‖ iv ‖ ciphertext（aad = header(8) only）。
 *
 * 安全：任何解密 / 解析 / 认证错误都【折叠为不透明 DecryptionException】（防 oracle，§5）。
 */

package org.unicodex.ucx

/**
 * 解析后的 UCXE 头部（不含密文 / tag 的具体字节，仅保存定位所需）。
 *
 * @property rawHeader8     头部前 8 字节（magic|ver|algo|kdf|raw_flags），用于 AAD 与 CBC HMAC。
 * @property algoId         算法 id（0x01/0x02/0x03）。
 * @property kdfId          KDF id（0x00/0x01/0x02）。
 * @property flags          原始 flags 字节（含 reserved bits）。
 * @property kdfParamsBytes KDF 参数块的原始 LE 字节（0/4/12）。
 * @property kdfSpec        解析出的 KDF 描述。
 * @property salt           盐字节。
 * @property iv             IV/Nonce 字节。
 * @property ciphertext     密文（chunked 模式下为序列化 chunk 流）。
 * @property tag            认证标签（chunked 模式下为零占位）。
 */
internal class UcxeHeader(
    val rawHeader8: ByteArray,
    val algoId: Int,
    val kdfId: Int,
    val flags: Int,
    val kdfParamsBytes: ByteArray,
    val kdfSpec: KdfSpec,
    val salt: ByteArray,
    val iv: ByteArray,
    val ciphertext: ByteArray,
    val tag: ByteArray,
) {
    /** 是否分块模式（flags bit0）。 */
    val chunked: Boolean get() = (flags and 0x01) != 0

    /**
     * AEAD 模式的 AAD = header(8) ‖ kdf_params ‖ salt（§7.6）。
     * 注意使用【原始 flags 字节】（rawHeader8 内已包含）。
     */
    fun aeadAad(): ByteArray = rawHeader8 + kdfParamsBytes + salt

    /** CBC 模式 HMAC 的 aad = header(8) only（§7.6）。 */
    fun cbcAad(): ByteArray = rawHeader8
}

/**
 * UCXE 解密入口。
 */
object UcxeCrypto {

    /** 前 4 字节是否等于 UCXE magic（§4.6）。 */
    @JvmStatic
    fun isUcxe(data: ByteArray): Boolean =
        ByteIO.regionEquals(data, 0, UcxConstants.UCXE_MAGIC)

    /**
     * 直接密钥解密（KDF=None；§4.6、§7.8）。
     *
     * @param ucxe UCXE 容器字节。
     * @param key  32 字节密钥。
     * @throws DecryptionException 任何失败（不透明）。
     */
    @JvmStatic
    fun decryptWithKey(ucxe: ByteArray, key: ByteArray): ByteArray {
        // 复制密钥以避免修改调用方的数组，解密后清零副本。
        var keyCopy: ByteArray? = null
        try {
            return runOpaque {
                val header = parse(ucxe)
                // 直接密钥模式要求 KDF=None。
                if (header.kdfId != UcxConstants.KDF_NONE) {
                    throw IllegalStateException("direct-key decrypt requires KDF=None")
                }
                if (key.size != 32) {
                    throw IllegalStateException("direct key must be 32 bytes")
                }
                // AES-CBC 在直接密钥模式被拒（需要 64 字节 = enc+mac）。
                if (header.algoId == UcxConstants.ALGO_AES_256_CBC) {
                    throw IllegalStateException("AES-CBC not allowed in direct-key mode")
                }
                keyCopy = key.copyOf()
                decryptWithRawKey(header, keyCopy!!)
            }
        } finally {
            // (P1 安全) best-effort 清零密钥材料，减少密钥在内存中的驻留时间。
            keyCopy?.fill(0)
        }
    }

    /**
     * 口令解密（KDF≠None；§4.6、§7.8）。
     *
     * @param ucxe       UCXE 容器字节。
     * @param passphrase 明文口令（将被 NFC 归一化）。
     * @throws DecryptionException 任何失败（不透明）。
     */
    @JvmStatic
    fun decryptWithPassphrase(ucxe: ByteArray, passphrase: String): ByteArray {
        var derived: ByteArray? = null
        var encKey: ByteArray? = null
        var macKey: ByteArray? = null
        try {
            return runOpaque {
                val header = parse(ucxe)
                if (header.kdfId == UcxConstants.KDF_NONE) {
                    throw IllegalStateException("passphrase decrypt requires a KDF (not None)")
                }
                // (§7.8, §8.3) 解密路径要求 salt 恰好 16 字节。
                if (header.salt.size != UcxConstants.SALT_LEN) {
                    throw IllegalStateException("salt must be exactly ${UcxConstants.SALT_LEN} bytes")
                }
                // 参数必须在解密前校验。
                Kdf.validate(header.kdfSpec)
                // 输出长度：AEAD 32；AES-CBC 64。
                val outLen = if (header.algoId == UcxConstants.ALGO_AES_256_CBC) 64 else 32
                derived = Kdf.derive(header.kdfSpec, passphrase, header.salt, outLen)
                when (header.algoId) {
                    UcxConstants.ALGO_AES_256_CBC -> {
                        encKey = derived!!.copyOfRange(0, 32)
                        macKey = derived!!.copyOfRange(32, 64)
                        Symmetric.decryptCbc(header, encKey!!, macKey!!)
                    }
                    else -> decryptWithRawKey(header, derived!!)
                }
            }
        } finally {
            // (P1 安全) best-effort 清零派生密钥材料。
            derived?.fill(0)
            encKey?.fill(0)
            macKey?.fill(0)
        }
    }

    // ---------------------------------------------------------------------------------
    // 内部实现
    // ---------------------------------------------------------------------------------

    /** 用一个 32 字节 AEAD 密钥解密（GCM / ChaCha20；非 CBC）。 */
    private fun decryptWithRawKey(header: UcxeHeader, key: ByteArray): ByteArray {
        return when (header.algoId) {
            UcxConstants.ALGO_AES_256_GCM,
            UcxConstants.ALGO_CHACHA20_POLY1305 -> {
                if (header.chunked) {
                    Symmetric.decryptChunkedAead(header, key)
                } else {
                    Symmetric.decryptAead(header, key)
                }
            }
            else -> throw IllegalStateException("unsupported algorithm for raw-key path")
        }
    }

    /**
     * 解析 UCXE 头部（§7.2）。任何越界 / 非法字段抛异常（由 runOpaque 折叠）。
     */
    internal fun parse(data: ByteArray): UcxeHeader {
        val cur = ByteCursor(data)

        // (1) magic
        val magic = cur.bytes(4)
        if (!magic.contentEquals(UcxConstants.UCXE_MAGIC)) {
            throw IllegalStateException("bad UCXE magic")
        }
        // (2) format version
        val ver = cur.u8()
        if (ver != UcxConstants.UCXE_FORMAT_VERSION) {
            throw IllegalStateException("unsupported UCXE version $ver")
        }
        // (3) algo id
        val algoId = cur.u8()
        if (algoId != UcxConstants.ALGO_AES_256_GCM &&
            algoId != UcxConstants.ALGO_AES_256_CBC &&
            algoId != UcxConstants.ALGO_CHACHA20_POLY1305
        ) {
            throw IllegalStateException("unknown algorithm id $algoId")
        }
        // (4) kdf id
        val kdfId = cur.u8()
        // (5) flags（原始字节，含 reserved bits）
        val flags = cur.u8()

        // rawHeader8 = data[0..8)（即 magic|ver|algo|kdf|raw_flags）。
        val rawHeader8 = data.copyOfRange(0, 8)

        // (6) KDF 参数块（依 kdfId 长度 0/4/12）
        val (kdfParamsBytes, kdfSpec) = when (kdfId) {
            UcxConstants.KDF_NONE -> Pair(ByteArray(0), KdfSpec.None)
            UcxConstants.KDF_ARGON2ID -> {
                val params = cur.bytes(12)
                val mem = ByteIO.readU32LE(params, 0)
                val time = ByteIO.readU32LE(params, 4)
                val par = ByteIO.readU32LE(params, 8)
                Pair(params, KdfSpec.Argon2id(mem, time, par))
            }
            UcxConstants.KDF_PBKDF2_HMAC_SHA256 -> {
                val params = cur.bytes(4)
                val iters = ByteIO.readU32LE(params, 0)
                Pair(params, KdfSpec.Pbkdf2(iters))
            }
            else -> throw IllegalStateException("unknown kdf id $kdfId")
        }

        // (7)(8) salt
        val saltLen = cur.u16le()
        if (saltLen > UcxConstants.MAX_SALT_LEN) {
            throw IllegalStateException("salt too long")
        }
        val salt = cur.bytes(saltLen)

        // (9)(10) iv
        val ivLen = cur.u16le()
        if (ivLen > UcxConstants.MAX_IV_LEN) {
            throw IllegalStateException("iv too long")
        }
        val iv = cur.bytes(ivLen)

        // (11)(12) ciphertext
        val ctLen = cur.u64le()
        if (ctLen < 0 || ctLen > UcxConstants.MAX_CIPHERTEXT_LEN) {
            throw IllegalStateException("ciphertext length out of range")
        }
        // (P2 安全) ctLen 是 u64，toInt() 在 >2GB 时会截断。
        // 在 JVM 上单个 ByteArray 不能超过 Integer.MAX_VALUE 字节，
        // 因此 ctLen > Int.MAX_VALUE 时直接拒绝以避免静默截断。
        if (ctLen > Int.MAX_VALUE.toLong()) {
            throw IllegalStateException("ciphertext length exceeds JVM array limit")
        }
        // tag 长度由算法决定（§7.3/§7.5）。
        val tagLen = when (algoId) {
            UcxConstants.ALGO_AES_256_GCM -> UcxConstants.GCM_TAG_LEN
            UcxConstants.ALGO_AES_256_CBC -> UcxConstants.CBC_MAC_LEN
            UcxConstants.ALGO_CHACHA20_POLY1305 -> UcxConstants.CHACHA_TAG_LEN
            else -> throw IllegalStateException("unreachable")
        }
        // ct_len + tag_len 必须 <= 剩余。
        if (ctLen + tagLen > cur.remaining().toLong()) {
            throw IllegalStateException("ciphertext + tag exceeds buffer")
        }
        val ciphertext = cur.bytes(ctLen.toInt())
        // (13) tag（无长度前缀，长度由算法决定）
        val tag = cur.bytes(tagLen)

        return UcxeHeader(
            rawHeader8 = rawHeader8,
            algoId = algoId,
            kdfId = kdfId,
            flags = flags,
            kdfParamsBytes = kdfParamsBytes,
            kdfSpec = kdfSpec,
            salt = salt,
            iv = iv,
            ciphertext = ciphertext,
            tag = tag,
        )
    }

    /**
     * 执行解密块，将任何异常（除 OOM 等致命错误）折叠为不透明 DecryptionException（§5、防 oracle）。
     */
    private inline fun runOpaque(block: () -> ByteArray): ByteArray {
        return try {
            block()
        } catch (e: DecryptionException) {
            throw e
        } catch (e: Exception) {
            // 不携带 cause，避免泄露具体失败原因。
            throw DecryptionException()
        }
    }
}
