/*
 * SPDX-License-Identifier: MIT
 *
 * SignatureVerifier.kt —— 双层 Ed25519 签名验证（UCX-FORMAT §6）。
 *
 * Layer 1（JAR 风格 SF/EC，§6.1）：
 *   EC 签 SF → SF 摘要 MANIFEST → MANIFEST 摘要每个文件。
 *   逐签名者：digest_matches && sig_valid && cert_time_valid && cert_pem_match。
 *
 * Layer 2（APK-v2 风格签名块，§6.2）：
 *   在最后 local file 数据与 Central Directory 之间，magic "UCX Sig Block 1\0"。
 *   逐签名者：digest_matches（分块摘要） && sig_valid（Ed25519 over signed_data） && cert_time_valid。
 *
 * 状态决策（§6 状态表）：两层都在→任一失败即 INVALID；仅一层在且有效→VALID_WITH_WARNINGS。
 */

package org.unicodex.ucx

internal object SignatureVerifier {

    private const val SIG_DIR = "META-INF/signatures/"
    private const val CERT_DIR = "META-INF/certs/"

    /** 单签名者的内部验证中间结果。 */
    private class SignerState(
        val signerId: String,
        var subjectCn: String? = null,
        var fingerprint: String? = null,
        var certType: String? = null,
        var layer1Present: Boolean = false,
        var layer1Valid: Boolean = false,
        var layer2Present: Boolean = false,
        var layer2Valid: Boolean = false,
    )

    /**
     * 验证整个归档的签名（§6）。
     */
    fun verify(zip: ZipReader): SignatureResult {
        // 以 signerId 聚合两层结果。
        val signers = LinkedHashMap<String, SignerState>()

        // ---- Layer 1 ----
        val l1 = verifyLayer1(zip, signers)
        // ---- Layer 2 ----
        val l2 = verifyLayer2(zip, signers)

        val layer1Present = l1.first
        val layer1Valid = l1.second
        val layer2Present = l2.first
        val layer2Valid = l2.second

        // 状态决策表（§6）。
        val status = when {
            !layer1Present && !layer2Present -> SignatureStatus.UNSIGNED
            layer1Present && layer2Present ->
                if (layer1Valid && layer2Valid) SignatureStatus.VERIFIED
                else SignatureStatus.INVALID
            // 仅一层存在。
            else -> {
                val onlyValid =
                    (layer1Present && layer1Valid) || (layer2Present && layer2Valid)
                if (onlyValid) SignatureStatus.VALID_WITH_WARNINGS else SignatureStatus.INVALID
            }
        }

        val signerList = signers.values.map {
            Signer(
                signerId = it.signerId,
                subjectCn = it.subjectCn,
                fingerprint = it.fingerprint,
                certType = it.certType,
                layer1Valid = it.layer1Valid,
                layer2Valid = it.layer2Valid,
            )
        }

        return SignatureResult(
            status = status,
            layer1Present = layer1Present,
            layer1Valid = layer1Valid,
            layer2Present = layer2Present,
            layer2Valid = layer2Valid,
            signers = signerList,
        )
    }

    // =================================================================================
    // Layer 1（§6.1）
    // =================================================================================

    /** @return Pair(present, valid)。 */
    private fun verifyLayer1(
        zip: ZipReader,
        signers: LinkedHashMap<String, SignerState>,
    ): Pair<Boolean, Boolean> {
        // 找出所有 META-INF/signatures/*.SF。
        val sfNames = zip.listNames().filter {
            it.startsWith(SIG_DIR) && it.endsWith(".SF")
        }
        if (sfNames.isEmpty()) return Pair(false, false)

        val manifestBytes = zip.read("META-INF/MANIFEST.MF") ?: return Pair(true, false)
        val manifestDigestB64 = Hashing.blake3Base64(manifestBytes)

        var allValid = true
        for (sfName in sfNames) {
            val signerId = sfName.removePrefix(SIG_DIR).removeSuffix(".SF")
            val state = signers.getOrPut(signerId) { SignerState(signerId) }
            state.layer1Present = true

            val valid = verifyLayer1Signer(zip, signerId, sfName, manifestDigestB64, state)
            state.layer1Valid = valid
            if (!valid) allValid = false
        }
        return Pair(true, allValid)
    }

    /** 验证单个 Layer 1 签名者；填充 state 元信息。 */
    private fun verifyLayer1Signer(
        zip: ZipReader,
        signerId: String,
        sfName: String,
        manifestDigestB64: String,
        state: SignerState,
    ): Boolean {
        try {
            val sfBytes = zip.read(sfName) ?: return false
            val ecBytes = zip.read("$SIG_DIR$signerId.EC") ?: return false

            // 步骤 2：SF 的 BLAKE3-Digest-Manifest 必须等于 Base64(BLAKE3(manifest))。
            // 使用常量时间比较，防止时间侧信道泄露摘要内容。
            val sfAttrs = parseSfMainHeaders(sfBytes)
            val sfManifestDigest = sfAttrs["BLAKE3-Digest-Manifest"] ?: return false
            val digestMatches = CryptoUtil.constantTimeEquals(sfManifestDigest, manifestDigestB64)

            // 步骤 3：解析 .EC blob，验证 Ed25519 over 原始 .SF 字节。
            val ec = parseEcBlob(ecBytes) ?: return false
            val cert = try {
                CertUtil.parseDer(ec.certDer)
            } catch (e: Exception) {
                return false
            }
            // 填充元信息（即便后续校验失败，也尽量给出 signer 信息）。
            state.subjectCn = cert.subjectCn
            state.fingerprint = cert.fingerprint()
            state.certType = cert.certType()

            val sigValid = CertUtil.verifyEd25519(cert.publicKey, sfBytes, ec.signature)

            // 步骤 4：证书有效期窗口。
            val certTimeValid = cert.isTimeValid()

            // 步骤 5：cert-PEM 交叉校验（若存在 PEM）。
            val pemName = "$CERT_DIR$signerId.cert.pem"
            val certPemMatch = if (zip.has(pemName)) {
                val pemBytes = zip.read(pemName)!!
                val pemDer = try {
                    CertUtil.pemCertToDer(pemBytes.toString(Charsets.UTF_8))
                } catch (e: Exception) {
                    return false
                }
                pemDer.contentEquals(ec.certDer)
            } else {
                true // 缺 PEM 允许（无交叉校验）。
            }

            return digestMatches && sigValid && certTimeValid && certPemMatch
        } catch (e: Exception) {
            return false
        }
    }

    /** 解析 SF 文本的主属性段（key: value 行），用于取 BLAKE3-Digest-Manifest。 */
    private fun parseSfMainHeaders(sfBytes: ByteArray): Map<String, String> {
        val text = sfBytes.toString(Charsets.UTF_8).replace("\r\n", "\n").replace("\r", "\n")
        val result = LinkedHashMap<String, String>()
        for (rawLine in text.split('\n')) {
            val line = rawLine.trim()
            if (line.isEmpty()) continue
            val idx = line.indexOf(": ")
            if (idx < 0) continue
            result[line.substring(0, idx)] = line.substring(idx + 2)
        }
        return result
    }

    /** .EC blob 的解析结果。 */
    private class EcBlob(val signature: ByteArray, val certDer: ByteArray)

    /**
     * 解析 .EC 自定义二进制 blob（§6.1）：
     *   algoId u32LE | sigLen u32LE | sig | certLen u32LE | certDER。
     */
    private fun parseEcBlob(ec: ByteArray): EcBlob? {
        return try {
            val cur = ByteCursor(ec)
            val algoId = cur.u32le()
            if (algoId != UcxConstants.SIG_ALGO_ED25519_BLAKE3.toLong()) return null
            val sigLen = cur.u32le()
            if (sigLen != UcxConstants.ED25519_SIG_LEN.toLong()) return null
            val signature = cur.bytes(sigLen.toInt())
            val certLen = cur.u32le()
            if (certLen <= 0 || certLen > cur.remaining().toLong()) return null
            val certDer = cur.bytes(certLen.toInt())
            EcBlob(signature, certDer)
        } catch (e: Exception) {
            null
        }
    }

    // =================================================================================
    // Layer 2（§6.2）
    // =================================================================================

    /** @return Pair(present, valid)。 */
    private fun verifyLayer2(
        zip: ZipReader,
        signers: LinkedHashMap<String, SignerState>,
    ): Pair<Boolean, Boolean> {
        val data = zip.rawBytes
        val located = try {
            locateBlock(data)
        } catch (e: Exception) {
            null
        } ?: return Pair(false, false)

        return try {
            val (blockStart, cdOffset) = located
            val block = data.copyOfRange(blockStart, cdOffset)

            // 重构受保护内容并计算分块摘要（§6.2.2）。
            val recomputed = computeProtectedDigest(data, blockStart, cdOffset)

            // 解析签名块内的签名者条目。
            val parsed = parseSigningBlock(block) ?: return Pair(true, false)

            var allValid = parsed.isNotEmpty()
            for (entry in parsed) {
                // 使用常量时间比较，防止时间侧信道泄露摘要内容。
                val digestMatches = CryptoUtil.constantTimeEquals(entry.digest, recomputed)
                // Ed25519 over signed_data（用 public_key；签名块内嵌 raw 公钥）。
                val sigValid =
                    CertUtil.verifyEd25519(entry.publicKey, entry.signedData, entry.signature)
                // 证书时间窗口。
                val cert = try {
                    CertUtil.parseDer(entry.certDer)
                } catch (e: Exception) {
                    null
                }
                val certTimeValid = cert?.isTimeValid() ?: false

                // 用 fingerprint 关联 signer（与 L1 同证书指纹时归并到同一 signerId）。
                val fp = cert?.fingerprint()
                val state = findOrAttachSigner(signers, fp)
                state.layer2Present = true
                val entryValid = digestMatches && sigValid && certTimeValid
                state.layer2Valid = entryValid
                if (cert != null) {
                    if (state.subjectCn == null) state.subjectCn = cert.subjectCn
                    if (state.fingerprint == null) state.fingerprint = fp
                    if (state.certType == null) state.certType = cert.certType()
                }
                if (!entryValid) allValid = false
            }
            Pair(true, allValid)
        } catch (e: Exception) {
            Pair(true, false)
        }
    }

    /**
     * 通过证书指纹将 Layer 2 条目关联到已有 signer（来自 Layer 1）；
     * 若无匹配则用 fingerprint 作为临时 signerId 新建。
     */
    private fun findOrAttachSigner(
        signers: LinkedHashMap<String, SignerState>,
        fingerprint: String?,
    ): SignerState {
        if (fingerprint != null) {
            val existing = signers.values.firstOrNull { it.fingerprint == fingerprint }
            if (existing != null) return existing
        }
        val key = fingerprint ?: "layer2"
        return signers.getOrPut(key) { SignerState(key) }
    }

    /**
     * 定位签名块（§6.2.1）。
     * @return Pair(blockStart, cdOffset)；不存在返回 null。
     */
    private fun locateBlock(data: ByteArray): Pair<Int, Int>? {
        val eocd = findEocd(data) ?: return null
        // CD offset 在 EOCD+16（u32 LE）。
        val cdOffset = ByteIO.readU32LE(data, eocd + 16).toInt()
        if (cdOffset < 0 || cdOffset > data.size) return null
        // CD 前 16 字节必须等于 magic。
        val magicStart = cdOffset - UcxConstants.L2_BLOCK_MAGIC.size
        if (magicStart < 0) return null
        if (!ByteIO.regionEquals(data, magicStart, UcxConstants.L2_BLOCK_MAGIC)) return null
        // 尾随 size_of_block 在 magicStart-8。
        val trailingSizePos = magicStart - 8
        if (trailingSizePos < 0) return null
        val sizeOfBlock = ByteIO.readU64LE(data, trailingSizePos)
        // block_start = cd_offset - 8 - size_of_block。
        val blockStart = (cdOffset.toLong() - 8L - sizeOfBlock).toInt()
        if (blockStart < 0 || blockStart >= cdOffset) return null
        // 起始 size_of_block 必须等于尾随。
        val leadingSize = ByteIO.readU64LE(data, blockStart)
        if (leadingSize != sizeOfBlock) return null
        return Pair(blockStart, cdOffset)
    }

    /** 反向扫描 EOCD（PK\x05\x06），返回 EOCD 起始偏移；找不到返回 null。 */
    private fun findEocd(data: ByteArray): Int? {
        // EOCD 最小 22 字节；comment 最长 65535。从尾部向前扫描。
        val minEocd = 22
        if (data.size < minEocd) return null
        val sig = byteArrayOf(0x50, 0x4B, 0x05, 0x06)
        val lowerBound = maxOf(0, data.size - (minEocd + 0xFFFF))
        var i = data.size - minEocd
        while (i >= lowerBound) {
            if (ByteIO.regionEquals(data, i, sig)) {
                // 校验 comment 长度与文件末尾一致。
                val commentLen = (data[i + 20].toInt() and 0xFF) or
                    ((data[i + 21].toInt() and 0xFF) shl 8)
                if (i + minEocd + commentLen == data.size) {
                    return i
                }
            }
            i--
        }
        return null
    }

    /**
     * 计算受保护内容的分块摘要（§6.2.2）。
     *
     * - entries = data[0 .. blockStart]
     * - cd_and_eocd = data[cdOffset .. end]
     * - original_zip = entries ‖ cd_and_eocd
     * - 然后把 original_zip 中 EOCD 的 CD-offset 字段回写为 cd_offset - block_size。
     * - protected = original_zip（= section1 entries ‖ section3 CD ‖ section4 EOCD）
     * - 1 MiB 分块；chunk_digest = BLAKE3(0xA5 ‖ u32le(len) ‖ chunk)
     * - top = BLAKE3(0x5A ‖ u32le(count) ‖ 各 chunk_digest 串接)
     */
    private fun computeProtectedDigest(data: ByteArray, blockStart: Int, cdOffset: Int): ByteArray {
        val blockSize = cdOffset - blockStart
        val entries = data.copyOfRange(0, blockStart)
        val cdAndEocd = data.copyOfRange(cdOffset, data.size)
        val original = entries + cdAndEocd

        // 回写 EOCD 的 CD-offset 字段：在 original 中定位 EOCD，再写 (cdOffset - blockSize)。
        val eocdInOriginal = findEocd(original)
            ?: throw IllegalStateException("EOCD not found in reconstructed zip")
        ByteIO.writeU32LEInto(original, eocdInOriginal + 16, (cdOffset - blockSize).toLong())

        // 分块（1 MiB），空输入 ⇒ 一个空 chunk。
        val chunkSize = UcxConstants.L2_CHUNK_SIZE
        val chunkDigests = ArrayList<ByteArray>()
        if (original.isEmpty()) {
            chunkDigests.add(chunkDigest(ByteArray(0)))
        } else {
            var off = 0
            while (off < original.size) {
                val end = minOf(off + chunkSize, original.size)
                chunkDigests.add(chunkDigest(original.copyOfRange(off, end)))
                off = end
            }
        }
        // top_digest = BLAKE3(0x5A ‖ u32le(count) ‖ chunkDigests...)
        val top = java.io.ByteArrayOutputStream()
        top.write(byteArrayOf(UcxConstants.L2_TOP_PREFIX))
        top.write(ByteIO.u32leBytes(chunkDigests.size.toLong()))
        for (cd in chunkDigests) top.write(cd)
        return Hashing.blake3(top.toByteArray())
    }

    /** chunk_digest = BLAKE3(0xA5 ‖ u32le(len(chunk)) ‖ chunk)。 */
    private fun chunkDigest(chunk: ByteArray): ByteArray {
        val buf = java.io.ByteArrayOutputStream()
        buf.write(byteArrayOf(UcxConstants.L2_CHUNK_PREFIX))
        buf.write(ByteIO.u32leBytes(chunk.size.toLong()))
        buf.write(chunk)
        return Hashing.blake3(buf.toByteArray())
    }

    /** Layer 2 单签名者解析结果。 */
    private class L2Signer(
        val signedData: ByteArray,
        val digest: ByteArray,
        val certDer: ByteArray,
        val signature: ByteArray,
        val publicKey: ByteArray,
    )

    /**
     * 解析签名块结构（§6.2）：
     *   size_of_block(u64) | pair_size(u64) | pair_id(u32) | signers_data | size_of_block(u64) | magic(16)
     * signers_data 内单个签名者：
     *   signed_data_len(u32) | signed_data{algoId(u32)|digest(32)|certLen(u32)|certDER} |
     *   sigAlgoId(u32) | sigLen(u32) | sig(64) | pubLen(u32) | pub(32)
     */
    private fun parseSigningBlock(block: ByteArray): List<L2Signer>? {
        return try {
            val cur = ByteCursor(block)
            cur.u64le() // 起始 size_of_block（已在 locateBlock 校验，忽略）
            val pairSize = cur.u64le()
            // pairSize 下界校验：至少包含 4 字节的 pair_id，否则减法下溢。
            if (pairSize < 4) return null
            // pairSize 上界校验：防止 u64 转 Int 时溢出（Long -> Int 截断）。
            if (pairSize > Int.MAX_VALUE.toLong()) return null
            val pairId = cur.u32le()
            if (pairId != UcxConstants.L2_PAIR_ID) return null
            // signers_data 长度 = pairSize - 4。
            val signersDataLen = (pairSize - 4).toInt()
            if (signersDataLen < 0 || signersDataLen > cur.remaining()) return null
            val signersData = cur.bytes(signersDataLen)

            // 当前参考实现写入单个签名者 blob；这里解析尽可能多的连续条目。
            val out = ArrayList<L2Signer>()
            val sc = ByteCursor(signersData)
            while (sc.remaining() > 0) {
                val signedDataLen = sc.u32le()
                if (signedDataLen <= 0 || signedDataLen > sc.remaining().toLong()) break
                val signedData = sc.bytes(signedDataLen.toInt())
                // 解析 signed_data：algoId|digest(32)|certLen|certDER。
                val sdCur = ByteCursor(signedData)
                val digestAlgoId = sdCur.u32le()
                if (digestAlgoId != UcxConstants.SIG_ALGO_ED25519_BLAKE3.toLong()) break
                val digest = sdCur.bytes(32)
                val certLen = sdCur.u32le()
                if (certLen <= 0 || certLen > sdCur.remaining().toLong()) break
                val certDer = sdCur.bytes(certLen.toInt())

                val sigAlgoId = sc.u32le()
                if (sigAlgoId != UcxConstants.SIG_ALGO_ED25519_BLAKE3.toLong()) break
                val sigLen = sc.u32le()
                if (sigLen != UcxConstants.ED25519_SIG_LEN.toLong()) break
                val signature = sc.bytes(sigLen.toInt())
                val pubLen = sc.u32le()
                if (pubLen != UcxConstants.ED25519_PUBKEY_LEN.toLong()) break
                val publicKey = sc.bytes(pubLen.toInt())

                out.add(L2Signer(signedData, digest, certDer, signature, publicKey))
            }
            out
        } catch (e: Exception) {
            null
        }
    }
}
