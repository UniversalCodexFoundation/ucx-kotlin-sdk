/*
 * SPDX-License-Identifier: MIT OR Apache-2.0
 *
 * Errors.kt —— Unicodex UCX 错误模型（SDK-API.md §5）。
 *
 * 统一的错误类别，映射到 Kotlin/JVM 惯用的异常类层级。所有 SDK 公开 API 在失败时
 * 抛出 UcxException 的子类。
 *
 * 关键安全约束：解密失败必须折叠为单一【不透明】的 DecryptionException —— 统一文案，
 * 不泄露具体原因（防 padding/tag oracle，对齐参考实现 ucx-crypto/src/lib.rs:138-152）。
 */

package org.unicodex.ucx

/**
 * 所有 UCX SDK 异常的基类。
 *
 * @param message 人类可读的错误描述。
 * @param cause   可选的底层异常（注意：DecryptionException 故意不携带 cause 以防 oracle）。
 */
sealed class UcxException(message: String, cause: Throwable? = null) :
    Exception(message, cause)

/**
 * InvalidFormat（SDK-API §5）：
 * 非 ZIP、mimetype 不符、UCX MAJOR>1、UCXE magic/version 非法等结构性错误。
 */
class InvalidFormatException(message: String, cause: Throwable? = null) :
    UcxException(message, cause)

/**
 * NotFound（SDK-API §5）：请求的条目 / 章节在归档中不存在。
 */
class NotFoundException(message: String) : UcxException(message)

/**
 * ParseError（SDK-API §5）：JSON / MANIFEST 解析失败。
 */
class ParseException(message: String, cause: Throwable? = null) :
    UcxException(message, cause)

/**
 * Unsupported（SDK-API §5）：本 SDK 未实现的算法 / KDF / 能力。
 * 对应 SDK-API §7 中 capabilities() 标 false 的项。
 */
class UnsupportedException(message: String) : UcxException(message)

/**
 * DecryptionError（SDK-API §5）：任何解密失败。
 *
 * 【不透明】：所有底层加密 / 解析 / 认证错误都折叠为同一文案，不携带 cause，
 * 以避免给攻击者提供区分错误类型的 oracle（防止 padding-oracle / tag-oracle 攻击）。
 * 这与参考实现 ucx-crypto/src/lib.rs:138-152 的语义一致。
 */
class DecryptionException internal constructor() :
    UcxException("decryption failed")

/**
 * IoError（SDK-API §5）：文件读写失败。I/O 错误可透传底层 cause。
 */
class UcxIoException(message: String, cause: Throwable? = null) :
    UcxException(message, cause)
