/*
 * SPDX-License-Identifier: MIT
 *
 * PathSafety.kt -- Zip-Slip 路径安全验证（UCX-FORMAT.md Security Requirements, item 3）。
 *
 * 参考 Rust 实现：ucx-types/src/path_safety.rs:97-170 validate_safe_relative_path()。
 *
 * 每一个 ZIP 条目名在解析时都必须经过此验证。拒绝以下路径模式：
 *   1. 空字符串
 *   2. 包含控制字符（code < 0x20，含 NUL）
 *   3. 包含反斜杠 '\'
 *   4. 以 '/' 开头（POSIX 绝对路径）
 *   5. 第二个字符是 ':' 且第一个是 ASCII 字母（Windows 驱动器前缀，如 "C:/"）
 *   6. 任何路径段（以 '/' 分隔）等于 ".."（父目录遍历）
 *   7. 任何路径段匹配 Windows 保留设备名（不区分大小写，含带扩展名形式）：
 *      CON, PRN, AUX, NUL, COM1-COM9, LPT1-LPT9
 *   8. 任何路径段以 '.' 或 ' ' 结尾（但单独的 "." 路径段允许）
 */

package org.unicodex.ucx

/**
 * ZIP 条目路径安全验证，防止 Zip-Slip 路径遍历攻击。
 */
internal object PathSafety {

    /**
     * Windows 保留设备名列表（全大写）。
     * 这些名称在 Windows 上不允许作为文件名使用，即使带有扩展名也不行。
     */
    private val WINDOWS_RESERVED = setOf(
        "CON", "PRN", "AUX", "NUL",
        "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
        "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    )

    /**
     * 验证 ZIP 条目名是否为安全的相对路径。
     *
     * 此函数必须在 ZIP 解析时对每个条目名调用。若路径不安全，
     * 抛出 [InvalidFormatException]。
     *
     * 参考 Rust 实现：ucx-types/src/path_safety.rs validate_safe_relative_path()。
     *
     * @param path ZIP 条目名
     * @throws InvalidFormatException 路径不安全
     */
    fun validateSafePath(path: String) {
        // 规则 1：拒绝空字符串。
        if (path.isEmpty()) {
            throw InvalidFormatException("ZIP entry name is empty")
        }

        // 规则 2：拒绝任何控制字符（code < 0x20，含 NUL）。
        for (i in path.indices) {
            if (path[i].code < 0x20) {
                throw InvalidFormatException(
                    "ZIP entry name contains control character at index $i: $path"
                )
            }
        }

        // 规则 3：拒绝反斜杠。
        if ('\\' in path) {
            throw InvalidFormatException(
                "ZIP entry name contains backslash: $path"
            )
        }

        // 规则 4：拒绝以 '/' 开头的绝对路径。
        if (path[0] == '/') {
            throw InvalidFormatException(
                "ZIP entry name starts with '/': $path"
            )
        }

        // 规则 5：拒绝 Windows 驱动器前缀（第二个字符为 ':'，第一个为 ASCII 字母）。
        if (path.length >= 2 && path[1] == ':'
            && path[0].isLetter() && path[0].code < 128
        ) {
            throw InvalidFormatException(
                "ZIP entry name has Windows drive prefix: $path"
            )
        }

        // 逐段检查（以 '/' 分隔）。
        val segments = path.split("/")
        for (seg in segments) {
            // 空段（连续斜杠或尾部斜杠）跳过 -- ZIP 条目名可以有 trailing slash（目录）。
            if (seg.isEmpty()) continue

            // 规则 6：拒绝 ".." 段（父目录遍历）。
            if (seg == "..") {
                throw InvalidFormatException(
                    "ZIP entry name contains '..' segment: $path"
                )
            }

            // 规则 7：拒绝 Windows 保留设备名（不区分大小写，含带扩展名形式）。
            // 例如 "CON"、"con.txt"、"NUL.tar.gz" 都被拒绝。
            val baseName = seg.substringBefore('.', seg)
            val baseUpper = if (baseName.isEmpty()) seg.uppercase() else baseName.uppercase()
            if (baseUpper in WINDOWS_RESERVED) {
                throw InvalidFormatException(
                    "ZIP entry name contains Windows reserved device name '$seg': $path"
                )
            }

            // 规则 8：拒绝以 '.' 或 ' ' 结尾的段（但单独的 "." 允许）。
            if (seg != ".") {
                val last = seg.last()
                if (last == '.' || last == ' ') {
                    throw InvalidFormatException(
                        "ZIP entry name segment ends with '$last': $path"
                    )
                }
            }
        }
    }
}
