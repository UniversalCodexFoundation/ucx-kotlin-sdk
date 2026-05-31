/*
 * SPDX-License-Identifier: MIT
 *
 * UcxArchive.kt —— UCX 归档句柄与只读阅读器入口（SDK-API.md §4）。
 *
 * open()/openBytes() 读取并校验容器（ZIP magic@0、mimetype），解析 codex/struct/manifest，
 * 返回一个 UcxArchive 句柄。后续元数据访问同步、章节读取按需。
 *
 * 本类聚合：
 *   - 解析（§4.1、§4.2）
 *   - 章节读取（§4.3）
 *   - 完整性校验（§4.4 → UCX-FORMAT §5）
 *   - 签名验证（§4.5，委托 SignatureVerifier）
 *   - 解密便捷方法（§4.6 便捷封装，委托 UcxeCrypto）
 */

package org.unicodex.ucx

import java.io.IOException
import java.nio.file.Files
import java.nio.file.Path

/**
 * UCX 归档句柄。通过 [UcxArchive.open] / [UcxArchive.openBytes] 创建。
 *
 * @property codex      作品元数据（metadata/codex.json）。
 * @property structure  内容树（content/struct.json）。
 * @property manifest   文件哈希清单（META-INF/MANIFEST.MF）。
 * @property filePath   若从文件打开则为路径，否则 null。
 */
class UcxArchive internal constructor(
    private val zip: ZipReader,
    val codex: Codex,
    val structure: Structure,
    val manifest: Manifest,
    val filePath: String?,
) {

    // =================================================================================
    // §4.2 元数据与结构
    // =================================================================================

    /**
     * 深度优先扁平化所有叶子节点为 Chapter 列表（按文档顺序）。
     * 叶子 = 有 file、无 children。归档内路径为 "content/{file}"。
     */
    fun chapters(): List<Chapter> {
        val result = ArrayList<Chapter>()
        fun walk(nodes: List<StructureNode>) {
            for (node in nodes) {
                val file = node.file
                if (file != null && node.children == null) {
                    result.add(Chapter(title = node.title, file = file, path = "content/$file"))
                } else if (node.children != null) {
                    walk(node.children)
                }
            }
        }
        walk(structure.nodes)
        return result
    }

    /** 归档内全部条目名（按写入顺序）。 */
    fun listFiles(): List<String> = zip.listNames()

    // =================================================================================
    // §4.3 章节读取
    // =================================================================================

    /**
     * 读取 content/{file} 的原始字节（可能是 UCXE 密文）。
     * @throws NotFoundException 条目不存在。
     */
    fun readChapter(file: String): ByteArray = zip.readRequired("content/$file")

    /** [readChapter] 的 UTF-8 解码便捷方法。 */
    fun readChapterText(file: String): String =
        readChapter(file).toString(Charsets.UTF_8)

    /** content/{file} 前 4 字节是否等于 UCXE magic。 */
    fun isChapterEncrypted(file: String): Boolean {
        val bytes = zip.read("content/$file")
            ?: throw NotFoundException("archive entry not found: content/$file")
        return UcxeCrypto.isUcxe(bytes)
    }

    // =================================================================================
    // §4.4 完整性校验（UCX-FORMAT §5）
    // =================================================================================

    /**
     * 对每个 manifest 条目重算 BLAKE3(解压字节) → Base64 → 比对 digest。
     * 缺失条目记为不通过（actual = ""）。
     */
    fun verifyIntegrity(): IntegrityResult {
        val entries = ArrayList<IntegrityEntry>()
        var allValid = true
        for (entry in manifest.entries) {
            val bytes = zip.read(entry.name)
            val actual = if (bytes == null) "" else Hashing.blake3Base64(bytes)
            // 使用常量时间比较，防止时间侧信道泄露摘要内容。
            val valid = bytes != null && CryptoUtil.constantTimeEquals(actual, entry.digest)
            if (!valid) allValid = false
            entries.add(
                IntegrityEntry(
                    name = entry.name,
                    expected = entry.digest,
                    actual = actual,
                    valid = valid,
                )
            )
        }
        return IntegrityResult(valid = allValid, entries = entries)
    }

    // =================================================================================
    // §4.5 签名验证（UCX-FORMAT §6）
    // =================================================================================

    /**
     * 验证 Layer1（SF/EC Ed25519）+ Layer2（签名块 Ed25519），按 UCX-FORMAT §6。
     */
    fun verifySignatures(): SignatureResult =
        SignatureVerifier.verify(zip)

    // =================================================================================
    // §4.6 解密便捷方法
    // =================================================================================

    /** 读取 content/{file} 并用直接密钥解密（KDF=None）。 */
    fun readChapterDecryptedWithKey(file: String, key: ByteArray): ByteArray =
        UcxeCrypto.decryptWithKey(readChapter(file), key)

    /** 读取 content/{file} 并用口令解密（NFC→KDF→AEAD/CBC）。 */
    fun readChapterDecryptedWithPassphrase(file: String, passphrase: String): ByteArray =
        UcxeCrypto.decryptWithPassphrase(readChapter(file), passphrase)

    companion object {

        /**
         * 从文件路径打开（§4.1）。
         * @throws UcxIoException 文件读取失败。
         * @throws InvalidFormatException / ParseException 见各自语义。
         */
        @JvmStatic
        fun open(path: String): UcxArchive {
            val bytes = try {
                Files.readAllBytes(Path.of(path))
            } catch (e: IOException) {
                throw UcxIoException("failed to read file: $path", e)
            }
            return build(bytes, path)
        }

        /** 从内存字节打开（§4.1）。 */
        @JvmStatic
        fun openBytes(data: ByteArray): UcxArchive = build(data, null)

        /** 内部构造：校验容器 → 解析 codex/struct/manifest。 */
        private fun build(data: ByteArray, filePath: String?): UcxArchive {
            val zip = ZipReader.open(data)

            // 解析 MANIFEST.MF（必需）。
            val manifestBytes = zip.read("META-INF/MANIFEST.MF")
                ?: throw InvalidFormatException("missing META-INF/MANIFEST.MF")
            val manifest = ManifestParser.parse(manifestBytes)

            // 解析 codex.json（必需）。
            val codexBytes = zip.read("metadata/codex.json")
                ?: throw InvalidFormatException("missing metadata/codex.json")
            val codex = UcxJson.toCodex(UcxJson.parseObject(codexBytes, "metadata/codex.json"))

            // 解析 struct.json（必需）。
            val structBytes = zip.read("content/struct.json")
                ?: throw InvalidFormatException("missing content/struct.json")
            val structure =
                UcxJson.toStructure(UcxJson.parseObject(structBytes, "content/struct.json"))

            return UcxArchive(zip, codex, structure, manifest, filePath)
        }
    }
}
