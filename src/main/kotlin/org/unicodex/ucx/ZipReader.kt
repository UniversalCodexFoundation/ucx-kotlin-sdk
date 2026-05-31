/*
 * SPDX-License-Identifier: MIT OR Apache-2.0
 *
 * ZipReader.kt —— UCX 容器（ZIP）读取（UCX-FORMAT §1、§2）。
 *
 * 该类同时承担两项职责：
 *   1) 提供【解压后的条目字节】，供 parse / integrity / 解密使用（哈希与签名都作用于解压字节）。
 *   2) 保留【原始磁盘字节】，供 Layer 2 签名块定位（§6.2）使用。
 *
 * 关键校验（§1、§2.1）：
 *   - 文件 offset 0 必须是 ZIP 本地文件头魔数 50 4B 03 04（拒绝 trailing-EOCD-only 归档）。
 *   - ZIP 第一个条目必须名为 "mimetype"，其（裁剪尾随空白后的）内容等于 mimetype 字符串。
 *
 * 解压使用 java.util.zip.ZipInputStream，它按【写入顺序】返回条目并自动 inflate，
 * 因此可直接判定 index 0 是否为 mimetype。
 */

package org.unicodex.ucx

import java.io.ByteArrayInputStream
import java.util.zip.ZipEntry
import java.util.zip.ZipInputStream

/**
 * 已读取的 ZIP 归档。
 *
 * @property rawBytes 原始磁盘字节（含可能存在的 Layer 2 签名块）。
 * @property orderedNames 按 ZIP 写入顺序排列的条目名。
 * @property entries 条目名 → 解压后字节 的映射。
 */
internal class ZipReader private constructor(
    val rawBytes: ByteArray,
    val orderedNames: List<String>,
    private val entries: Map<String, ByteArray>,
) {

    /** 是否存在某条目。 */
    fun has(name: String): Boolean = entries.containsKey(name)

    /** 取条目解压后的字节；不存在返回 null。 */
    fun read(name: String): ByteArray? = entries[name]

    /** 取条目解压后的字节；不存在抛 NotFoundException。 */
    fun readRequired(name: String): ByteArray =
        entries[name] ?: throw NotFoundException("archive entry not found: $name")

    /** 全部条目名（按写入顺序）。 */
    fun listNames(): List<String> = orderedNames

    companion object {

        /**
         * 从内存字节打开 ZIP 并执行 UCX 容器级校验。
         *
         * @throws InvalidFormatException 非 ZIP / mimetype 不符 / 容器结构非法。
         * @throws ParseException ZIP 解压失败。
         */
        fun open(data: ByteArray): ZipReader {
            // (§1) offset 0 必须是 ZIP 本地文件头魔数。
            if (data.size < 4 || !regionEquals(data, 0, UcxConstants.ZIP_MAGIC)) {
                throw InvalidFormatException(
                    "not a ZIP archive (missing PK\\x03\\x04 magic at offset 0)"
                )
            }

            val names = ArrayList<String>()
            val map = LinkedHashMap<String, ByteArray>()
            // 记录第一个条目的压缩方法，用于 mimetype STORED 校验（§2.1）。
            var firstEntryMethod: Int = -1

            try {
                ZipInputStream(ByteArrayInputStream(data)).use { zis ->
                    var entry = zis.nextEntry
                    while (entry != null) {
                        // 目录条目无内容，跳过（UCX 不写目录条目，但稳妥起见）。
                        if (!entry.isDirectory) {
                            val name = entry.name
                            // (Zip-Slip) 对每个条目名做路径安全验证，拒绝路径遍历、
                            // 控制字符、Windows 保留设备名等恶意路径模式。
                            // 参考 Rust ucx-types/src/path_safety.rs。
                            PathSafety.validateSafePath(name)
                            val bytes = zis.readBytes()
                            // 记录第一个条目的压缩方法。
                            if (names.isEmpty()) {
                                firstEntryMethod = entry.method
                            }
                            names.add(name)
                            // 同名条目以首次出现为准（ZIP 理论上不应重名）。
                            map.putIfAbsent(name, bytes)
                        }
                        zis.closeEntry()
                        entry = zis.nextEntry
                    }
                }
            } catch (e: InvalidFormatException) {
                // Zip-Slip 验证抛出的 InvalidFormatException 直接透传。
                throw e
            } catch (e: Exception) {
                throw ParseException("failed to read ZIP entries", e)
            }

            if (names.isEmpty()) {
                throw InvalidFormatException("empty ZIP archive")
            }

            // (§2.1) index 0 必须是 mimetype。
            if (names[0] != "mimetype") {
                throw InvalidFormatException(
                    "first ZIP entry must be 'mimetype', found '${names[0]}'"
                )
            }
            // (P2 合规) mimetype 条目必须使用 STORED 压缩方式（ZipEntry.STORED == 0）。
            // ZipInputStream 会透明解压，但规范要求 STORED 以便其他工具直接读取 mimetype 字节。
            if (firstEntryMethod != ZipEntry.STORED) {
                throw InvalidFormatException(
                    "mimetype entry must use STORED compression (method 0), found method $firstEntryMethod"
                )
            }
            val mimeBytes = map["mimetype"]
                ?: throw InvalidFormatException("mimetype entry has no content")
            // 比较时裁剪尾随空白 / 换行（§2.1：写入端无尾随换行，但读取端容忍）。
            val mime = mimeBytes.toString(Charsets.UTF_8).trim()
            if (mime != UcxConstants.MIMETYPE) {
                throw InvalidFormatException(
                    "invalid mimetype: expected '${UcxConstants.MIMETYPE}', found '$mime'"
                )
            }

            return ZipReader(data, names, map)
        }

        /** 比较 data[offset..offset+pattern.size) 是否逐字节等于 pattern。 */
        private fun regionEquals(data: ByteArray, offset: Int, pattern: ByteArray): Boolean {
            if (offset + pattern.size > data.size) return false
            for (i in pattern.indices) {
                if (data[offset + i] != pattern[i]) return false
            }
            return true
        }
    }
}
