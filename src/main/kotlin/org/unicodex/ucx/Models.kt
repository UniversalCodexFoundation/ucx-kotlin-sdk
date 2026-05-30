/*
 * SPDX-License-Identifier: MIT OR Apache-2.0
 *
 * Models.kt —— Unicodex UCX 数据模型（SDK-API.md §3）。
 *
 * 这些数据类是 codex.json / struct.json / MANIFEST.MF 解析后的内存表示。字段命名遵循
 * SDK-API §2 的 Kotlin 本地化映射（camelCase）；每个结构都带一个 `raw` 字段以前向兼容
 * 未建模的 JSON 字段。
 *
 * 设计原则（SDK-API §1.2）：解析永不失败于未知字段；缺失的可选字段用 null 表示。
 */

package org.unicodex.ucx

import kotlinx.serialization.json.JsonObject

// =====================================================================================
// Codex（metadata/codex.json，UCX-FORMAT §4.1）
// =====================================================================================

/** 作品标题。`title.main` 必填，其余可选。 */
data class Title(
    val main: String,
    val subtitle: String? = null,
    val original: String? = null,
    val short: String? = null,
)

/** 创作者。`name` 与 `role` 必填；`signatureRef` 链接到某个签名者 id。 */
data class Creator(
    val name: String,
    val role: String,
    val signatureRef: String? = null,
)

/** 作品标识符。`ucxId` 必填，形如 "urn:ucx:{uuidv4}"。 */
data class Identifier(
    val ucxId: String,
    val isbn: String? = null,
    val issn: String? = null,
    val doi: String? = null,
    val custom: Map<String, String>? = null,
)

/** 系列信息。 */
data class Series(
    val name: String,
    val index: Long? = null,
    val total: Long? = null,
)

/** 出版者。 */
data class Publisher(
    val name: String,
    val imprint: String? = null,
    val signatureRef: String? = null,
)

/** 描述（短 / 长）。 */
data class Description(
    val short: String? = null,
    val long: String? = null,
)

/** 权利声明。 */
data class Rights(
    val statement: String? = null,
    val license: String? = null,
)

/** 日期（ISO-8601 字符串）。 */
data class Dates(
    val created: String? = null,
    val published: String? = null,
    val modified: String? = null,
)

/** 分级。 */
data class Rating(
    val system: String,
    val value: String,
)

/** 文件版本元信息。 */
data class FileVersion(
    val version: String? = null,
    val revision: Long? = null,
    val releasedAt: String? = null,
    val changelog: String? = null,
)

/**
 * Codex —— 作品元数据（metadata/codex.json）。
 *
 * 必填字段：ucxId、title、creators(≥1)、language、identifier、schemaVersion。
 * 其余字段在 JSON 中缺失时为 null。`raw` 持有原始 JsonObject，便于前向兼容。
 */
data class Codex(
    /** = identifier.ucxId，形如 "urn:ucx:{uuidv4}"。 */
    val ucxId: String,
    val title: Title,
    val creators: List<Creator>,
    /** BCP-47 语言代码，如 "en"、"zh-CN"。 */
    val language: String,
    val identifier: Identifier,
    /** = codex.json 顶层 "version"。 */
    val schemaVersion: String,
    val series: Series? = null,
    val publisher: Publisher? = null,
    val genre: List<String>? = null,
    val tags: List<String>? = null,
    val status: String? = null,
    val wordCount: Long? = null,
    val description: Description? = null,
    val rights: Rights? = null,
    val dates: Dates? = null,
    val cover: String? = null,
    val rating: Rating? = null,
    val fileVersion: FileVersion? = null,
    /** 原始已解析 JSON，前向兼容未建模字段。 */
    val raw: JsonObject,
)

// =====================================================================================
// Structure（content/struct.json，UCX-FORMAT §4.2）
// =====================================================================================

/**
 * 结构节点（递归）。
 *
 * leaf（叶子）：有 `file`、无 `children`；container（容器）：有 `children`、无 `file`。
 * `title` 是唯一必填字段。`type` 对应 JSON key "type"（Rust 字段名 node_type）。
 */
data class StructureNode(
    val title: String,
    /** 相对 content/ 的路径（叶子节点）。与 children 互斥。 */
    val file: String? = null,
    /** 子节点列表（容器节点）。与 file 互斥。 */
    val children: List<StructureNode>? = null,
    val type: String? = null,
    val id: String? = null,
    val name: String? = null,
    val style: String? = null,
    /** 加密元信息（仅叶子有意义）；见 UCX-FORMAT §4.2。保留为原始 JsonObject。 */
    val encryption: JsonObject? = null,
)

/**
 * Structure —— 内容树（content/struct.json）。
 */
data class Structure(
    /** = struct.json 顶层 "version"。 */
    val schemaVersion: String,
    val nodes: List<StructureNode>,
    /** 原始已解析 JSON。 */
    val raw: JsonObject,
)

/**
 * Chapter —— chapters() 扁平化后的叶子节点视图。
 */
data class Chapter(
    val title: String,
    /** 相对 content/ 的路径，如 "chapter-001.md"。 */
    val file: String,
    /** 归档内绝对路径 "content/{file}"。 */
    val path: String,
)

// =====================================================================================
// Manifest（META-INF/MANIFEST.MF，UCX-FORMAT §3）
// =====================================================================================

/**
 * 单条 MANIFEST 条目。
 *
 * @property name        归档相对路径。
 * @property size        存储（密文，若加密）字节数。
 * @property digest      Base64-standard(padded) 的原始 BLAKE3 哈希；【NOT hex】。
 * @property encrypted   是否加密（默认 false）。
 * @property originalSize 仅加密条目存在：明文字节数。
 */
data class ManifestEntry(
    val name: String,
    val size: Long,
    val digest: String,
    val encrypted: Boolean = false,
    val originalSize: Long? = null,
)

/**
 * Manifest —— 文件哈希清单。
 *
 * @property hashAlgorithm "BLAKE3" | "SHA256" | "SHA512"（参考实现只产出 BLAKE3）。
 */
data class Manifest(
    val manifestVersion: String,
    val ucxVersion: String,
    val createdBy: String? = null,
    val hashAlgorithm: String,
    val entries: List<ManifestEntry>,
)

// =====================================================================================
// 完整性结果（IntegrityResult，UCX-FORMAT §5）
// =====================================================================================

/** 单条完整性校验结果。 */
data class IntegrityEntry(
    val name: String,
    /** manifest 中记录的期望 digest（Base64）。 */
    val expected: String,
    /** 实际重算得到的 digest（Base64）。 */
    val actual: String,
    val valid: Boolean,
)

/** 完整性校验总结果。`valid` 为所有条目均通过。 */
data class IntegrityResult(
    val valid: Boolean,
    val entries: List<IntegrityEntry>,
)

// =====================================================================================
// 签名结果（SignatureResult，UCX-FORMAT §6）
// =====================================================================================

/**
 * 签名状态枚举（SDK-API §3）。
 *
 * 判定严格遵循 UCX-FORMAT §6 状态表：
 *  - 都不在 → UNSIGNED
 *  - 两层都在且都有效 → VERIFIED
 *  - 两层都在、任一失败 → INVALID
 *  - 仅一层在且有效 → VALID_WITH_WARNINGS
 *  - 仅一层在但无效 → INVALID
 */
enum class SignatureStatus {
    UNSIGNED,
    VERIFIED,
    VALID_WITH_WARNINGS,
    INVALID,
}

/**
 * 单个签名者的验证结果。
 */
data class Signer(
    /** 来自 META-INF/signatures/{SIGNER}.SF 的文件名 stem。 */
    val signerId: String,
    val subjectCn: String? = null,
    /** lowercase-hex BLAKE3(cert_der)，64 hex 字符。 */
    val fingerprint: String? = null,
    /** "self-signed" | "ca-issued"。 */
    val certType: String? = null,
    val layer1Valid: Boolean,
    val layer2Valid: Boolean,
)

/**
 * 签名验证总结果（SDK-API §3）。
 */
data class SignatureResult(
    val status: SignatureStatus,
    val layer1Present: Boolean,
    val layer1Valid: Boolean,
    val layer2Present: Boolean,
    val layer2Valid: Boolean,
    val signers: List<Signer>,
)

// =====================================================================================
// 能力（Capabilities，SDK-API §7）
// =====================================================================================

/**
 * 能力声明（SDK-API §7）。`capabilities()` 返回该结构，如实声明本 SDK 达到的等级。
 */
data class Capabilities(
    /** 恒 true（L1 解析）。 */
    val parse: Boolean,
    /** BLAKE3 完整性可用（L1）。 */
    val integrity: Boolean,
    /** Ed25519 双层验签可用（L2）。 */
    val verifySignatures: Boolean,
    /** 直接密钥解密可用（L3）。 */
    val decryptDirectKey: Boolean,
    /** 口令解密可用（L3）。 */
    val decryptPassphrase: Boolean,
    /** 实际支持的对称算法子集。 */
    val algorithms: List<String>,
    /** 实际支持的 KDF 子集。 */
    val kdfs: List<String>,
)
