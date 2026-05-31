/*
 * SPDX-License-Identifier: MIT
 *
 * ManifestParser.kt —— META-INF/MANIFEST.MF 文本解析（UCX-FORMAT §3）。
 *
 * 文法（RFC-822-ish，`ucx-types/src/manifest.rs:160-300`）：
 *   - section 之间用空行（"\n\n"）分隔。
 *   - 每行形如 "Key: Value"，解析器在【第一个 ": "（冒号+空格）】处分割。
 *   - 第一个 section 为 main section（Manifest-Version 等）；其后每个 section 为一条 per-file 条目。
 *
 * digest 编码为 Base64-standard(padded) 的【原始 BLAKE3】（NOT hex）。`manifest.rs:23,343-347`
 */

package org.unicodex.ucx

/**
 * MANIFEST.MF 解析器。
 */
internal object ManifestParser {

    /**
     * 解析 MANIFEST.MF 字节为 Manifest 模型。
     *
     * @param bytes MANIFEST.MF 的原始解压字节。
     * @throws ParseException 当必填字段缺失或 UCX MAJOR > 1 时。
     */
    fun parse(bytes: ByteArray): Manifest {
        val text = bytes.toString(Charsets.UTF_8)

        // 按空行分割 section。用正则匹配一个或多个空白行序列（兼容 \r\n 与 \n）。
        // 每个 section 内部按行解析 Key: Value。
        val sections = splitSections(text)
        if (sections.isEmpty()) {
            throw ParseException("MANIFEST.MF is empty")
        }

        // ---- main section ----
        val mainAttrs = parseAttributes(sections[0])
        val manifestVersion = mainAttrs["Manifest-Version"]
            ?: throw ParseException("MANIFEST.MF missing 'Manifest-Version'")
        val ucxVersion = mainAttrs["UCX-Version"]
            ?: throw ParseException("MANIFEST.MF missing 'UCX-Version'")
        val hashAlgorithm = mainAttrs["Hash-Algorithm"]
            ?: throw ParseException("MANIFEST.MF missing 'Hash-Algorithm'")
        val createdBy = mainAttrs["Created-By"]

        // 拒绝 MAJOR > 1（UCX-FORMAT §3.1、§9）。
        val major = ucxVersion.substringBefore('.').toIntOrNull()
            ?: throw ParseException("MANIFEST.MF has malformed UCX-Version '$ucxVersion'")
        if (major > UcxConstants.SUPPORTED_UCX_MAJOR) {
            throw InvalidFormatException(
                "unsupported UCX major version $major (max ${UcxConstants.SUPPORTED_UCX_MAJOR})"
            )
        }

        // ---- per-file sections ----
        val digestHeaderSuffix = "-Digest"
        val entries = ArrayList<ManifestEntry>()
        for (i in 1 until sections.size) {
            val attrs = parseAttributes(sections[i])
            // 空 section（连续空行造成）跳过。
            if (attrs.isEmpty()) continue
            val name = attrs["Name"] ?: continue
            val size = attrs["Size"]?.toLongOrNull()
                ?: throw ParseException("manifest entry '$name' has invalid Size")
            // digest header 名为 "{ALGO}-Digest"，如 "BLAKE3-Digest"。
            val digest = attrs.entries.firstOrNull { it.key.endsWith(digestHeaderSuffix) }?.value
                ?: throw ParseException("manifest entry '$name' missing {ALGO}-Digest")
            val encrypted = attrs["Encrypted"] == "true"
            val originalSize = attrs["Original-Size"]?.toLongOrNull()
            entries.add(
                ManifestEntry(
                    name = name,
                    size = size,
                    digest = digest,
                    encrypted = encrypted,
                    originalSize = originalSize,
                )
            )
        }

        return Manifest(
            manifestVersion = manifestVersion,
            ucxVersion = ucxVersion,
            createdBy = createdBy,
            hashAlgorithm = hashAlgorithm,
            entries = entries,
        )
    }

    /**
     * 按空行将文本分割为多个 section。
     * 兼容 "\n\n"（Unix）与 "\r\n\r\n"（Windows）。尾随空白被裁剪。
     */
    private fun splitSections(text: String): List<String> {
        // 先统一换行为 \n 以简化分割（仅用于分段；不影响外层 §6 对原始字节的哈希）。
        val normalized = text.replace("\r\n", "\n").replace("\r", "\n")
        return normalized.split(Regex("\n[ \t]*\n"))
            .map { it.trim('\n') }
            .filter { it.isNotBlank() }
    }

    /**
     * 解析单个 section 的 "Key: Value" 行。
     * 在第一个 ": "（冒号+空格）处分割键与值（与参考实现 manifest.rs:189 一致）。
     */
    private fun parseAttributes(section: String): Map<String, String> {
        val result = LinkedHashMap<String, String>()
        for (rawLine in section.split('\n')) {
            val line = rawLine.trimEnd('\r')
            if (line.isBlank()) continue
            val idx = line.indexOf(": ")
            if (idx < 0) continue
            val key = line.substring(0, idx)
            val value = line.substring(idx + 2)
            result[key] = value
        }
        return result
    }
}
