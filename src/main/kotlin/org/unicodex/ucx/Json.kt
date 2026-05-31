/*
 * SPDX-License-Identifier: MIT
 *
 * Json.kt —— codex.json / struct.json 的 JSON 反序列化（UCX-FORMAT §4）。
 *
 * 采用 kotlinx.serialization 的 JsonElement DOM 进行【宽松】解析：未知字段被忽略，
 * 缺失的可选字段返回 null（SDK-API §1.2）。之所以手写 DOM → 模型映射，而非依赖
 * @Serializable 自动派生，是为了：
 *   1) 同时填充强类型字段与 `raw: JsonObject`（前向兼容）；
 *   2) 完成 JSON snake_case → Kotlin camelCase 的键名映射（如 ucx_id → ucxId）；
 *   3) 对必填字段缺失抛出 ParseException，符合 §5 错误模型。
 */

package org.unicodex.ucx

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.longOrNull

/**
 * JSON 解析工具。所有方法都对“未知字段宽松、缺失可选字段返回 null”负责。
 */
internal object UcxJson {

    /** 共享的宽松 JSON 解析器。`ignoreUnknownKeys` 与参考实现的 permissive 反序列化对齐。 */
    val parser: Json = Json {
        ignoreUnknownKeys = true
        isLenient = true
    }

    /** 将字节解析为顶层 JsonObject，失败抛 ParseException。 */
    fun parseObject(bytes: ByteArray, what: String): JsonObject =
        try {
            parser.parseToJsonElement(bytes.toString(Charsets.UTF_8)).jsonObject
        } catch (e: Exception) {
            throw ParseException("failed to parse $what as JSON object", e)
        }

    // ---- 小工具：从 JsonObject 安全取值 ----

    private fun JsonObject.str(key: String): String? =
        (this[key] as? JsonPrimitive)?.contentOrNull

    private fun JsonObject.strRequired(key: String, what: String): String =
        str(key) ?: throw ParseException("missing required field '$key' in $what")

    private fun JsonObject.long(key: String): Long? =
        (this[key] as? JsonPrimitive)?.longOrNull

    private fun JsonObject.bool(key: String): Boolean? =
        (this[key] as? JsonPrimitive)?.booleanOrNull

    private fun JsonObject.obj(key: String): JsonObject? =
        this[key] as? JsonObject

    private fun JsonObject.arr(key: String): JsonArray? =
        this[key] as? JsonArray

    private fun JsonElement.asStringList(): List<String> =
        (this as? JsonArray)?.mapNotNull { (it as? JsonPrimitive)?.contentOrNull }
            ?: emptyList()

    private fun JsonElement.asStringMap(): Map<String, String> =
        (this as? JsonObject)?.mapNotNull { (k, v) ->
            (v as? JsonPrimitive)?.contentOrNull?.let { k to it }
        }?.toMap() ?: emptyMap()

    // =================================================================================
    // Codex 映射（UCX-FORMAT §4.1）
    // =================================================================================

    /** 将 codex.json 的 JsonObject 映射为强类型 Codex。 */
    fun toCodex(root: JsonObject): Codex {
        val what = "codex.json"
        val identifierObj = root.obj("identifier")
            ?: throw ParseException("missing required field 'identifier' in $what")
        val identifier = Identifier(
            ucxId = identifierObj.strRequired("ucx_id", "$what.identifier"),
            isbn = identifierObj.str("isbn"),
            issn = identifierObj.str("issn"),
            doi = identifierObj.str("doi"),
            custom = identifierObj.obj("custom")?.asStringMap(),
        )

        val titleObj = root.obj("title")
            ?: throw ParseException("missing required field 'title' in $what")
        val title = Title(
            main = titleObj.strRequired("main", "$what.title"),
            subtitle = titleObj.str("subtitle"),
            original = titleObj.str("original"),
            short = titleObj.str("short"),
        )

        val creatorsArr = root.arr("creators")
            ?: throw ParseException("missing required field 'creators' in $what")
        val creators = creatorsArr.map { el ->
            val o = el.jsonObject
            Creator(
                name = o.strRequired("name", "$what.creators[]"),
                role = o.strRequired("role", "$what.creators[]"),
                signatureRef = o.str("signature_ref"),
            )
        }
        if (creators.isEmpty()) {
            throw ParseException("'creators' must have at least one entry in $what")
        }

        return Codex(
            ucxId = identifier.ucxId,
            title = title,
            creators = creators,
            language = root.strRequired("language", what),
            identifier = identifier,
            schemaVersion = root.strRequired("version", what),
            series = root.obj("series")?.let {
                Series(
                    name = it.strRequired("name", "$what.series"),
                    index = it.long("index"),
                    total = it.long("total"),
                )
            },
            publisher = root.obj("publisher")?.let {
                Publisher(
                    name = it.strRequired("name", "$what.publisher"),
                    imprint = it.str("imprint"),
                    signatureRef = it.str("signature_ref"),
                )
            },
            genre = root["genre"]?.asStringList(),
            tags = root["tags"]?.asStringList(),
            status = root.str("status"),
            wordCount = root.long("word_count"),
            description = root.obj("description")?.let {
                Description(short = it.str("short"), long = it.str("long"))
            },
            rights = root.obj("rights")?.let {
                Rights(statement = it.str("statement"), license = it.str("license"))
            },
            dates = root.obj("dates")?.let {
                Dates(
                    created = it.str("created"),
                    published = it.str("published"),
                    modified = it.str("modified"),
                )
            },
            cover = root.str("cover"),
            rating = root.obj("rating")?.let {
                Rating(
                    system = it.strRequired("system", "$what.rating"),
                    value = it.strRequired("value", "$what.rating"),
                )
            },
            fileVersion = root.obj("file_version")?.let {
                FileVersion(
                    version = it.str("version"),
                    revision = it.long("revision"),
                    releasedAt = it.str("released_at"),
                    changelog = it.str("changelog"),
                )
            },
            raw = root,
        )
    }

    // =================================================================================
    // Structure 映射（UCX-FORMAT §4.2）
    // =================================================================================

    /** 将 struct.json 的 JsonObject 映射为强类型 Structure。 */
    fun toStructure(root: JsonObject): Structure {
        val what = "struct.json"
        val structArr = root.arr("structure")
            ?: throw ParseException("missing required field 'structure' in $what")
        return Structure(
            schemaVersion = root.strRequired("version", what),
            nodes = structArr.map { toStructureNode(it.jsonObject, what) },
            raw = root,
        )
    }

    /** 递归映射单个 StructureNode。 */
    private fun toStructureNode(o: JsonObject, what: String): StructureNode {
        return StructureNode(
            title = o.strRequired("title", "$what.structure[]"),
            file = o.str("file"),
            children = o.arr("children")?.map { toStructureNode(it.jsonObject, what) },
            // JSON key 是 "type"（Rust 字段名 node_type）。
            type = o.str("type"),
            id = o.str("id"),
            name = o.str("name"),
            style = o.str("style"),
            encryption = o.obj("encryption"),
        )
    }
}
