/*
 * SPDX-License-Identifier: MIT
 *
 * ByteIO.kt —— 字节序与缓冲读取工具（UCXE / Layer2 解析用）。
 *
 * UCXE 头部与 Layer 2 签名块的所有整数均为【小端 LE】（chunk index 除外，那是大端 BE）。
 */

package org.unicodex.ucx

/**
 * 顺序读取字节缓冲区的小工具。越界读取抛 IndexOutOfBoundsException（由调用方折叠为业务错误）。
 */
internal class ByteCursor(val data: ByteArray, start: Int = 0) {
    /** 当前读取位置。 */
    var pos: Int = start
        private set

    /** 剩余可读字节数。 */
    fun remaining(): Int = data.size - pos

    /** 读取一个字节（无符号 0..255）。 */
    fun u8(): Int {
        require(pos + 1 <= data.size) { "u8 out of bounds" }
        return data[pos++].toInt() and 0xFF
    }

    /** 读取 u16 LE。 */
    fun u16le(): Int {
        require(pos + 2 <= data.size) { "u16 out of bounds" }
        val v = (data[pos].toInt() and 0xFF) or ((data[pos + 1].toInt() and 0xFF) shl 8)
        pos += 2
        return v
    }

    /** 读取 u32 LE（返回 Long 以避免符号问题）。 */
    fun u32le(): Long {
        require(pos + 4 <= data.size) { "u32 out of bounds" }
        var v = 0L
        for (i in 0 until 4) {
            v = v or ((data[pos + i].toLong() and 0xFF) shl (8 * i))
        }
        pos += 4
        return v
    }

    /** 读取 u64 LE。 */
    fun u64le(): Long {
        require(pos + 8 <= data.size) { "u64 out of bounds" }
        var v = 0L
        for (i in 0 until 8) {
            v = v or ((data[pos + i].toLong() and 0xFF) shl (8 * i))
        }
        pos += 8
        return v
    }

    /** 读取 n 字节切片（复制）。 */
    fun bytes(n: Int): ByteArray {
        require(n >= 0 && pos + n <= data.size) { "bytes($n) out of bounds" }
        val out = data.copyOfRange(pos, pos + n)
        pos += n
        return out
    }
}

/** 小端 / 大端编码辅助。 */
internal object ByteIO {

    /** 读 u32 LE（无符号，返回 Long）于任意偏移。 */
    fun readU32LE(data: ByteArray, offset: Int): Long {
        var v = 0L
        for (i in 0 until 4) {
            v = v or ((data[offset + i].toLong() and 0xFF) shl (8 * i))
        }
        return v
    }

    /** 读 u64 LE 于任意偏移。 */
    fun readU64LE(data: ByteArray, offset: Int): Long {
        var v = 0L
        for (i in 0 until 8) {
            v = v or ((data[offset + i].toLong() and 0xFF) shl (8 * i))
        }
        return v
    }

    /** 写 u32 LE 为 4 字节。 */
    fun u32leBytes(value: Long): ByteArray {
        val out = ByteArray(4)
        for (i in 0 until 4) {
            out[i] = ((value ushr (8 * i)) and 0xFF).toByte()
        }
        return out
    }

    /** 写 u32 BE 为 4 字节（chunk 子 nonce 用）。 */
    fun u32beBytes(value: Long): ByteArray {
        val out = ByteArray(4)
        for (i in 0 until 4) {
            out[3 - i] = ((value ushr (8 * i)) and 0xFF).toByte()
        }
        return out
    }

    /** 原位写入 u32 LE 到 data[offset..offset+4)。 */
    fun writeU32LEInto(data: ByteArray, offset: Int, value: Long) {
        for (i in 0 until 4) {
            data[offset + i] = ((value ushr (8 * i)) and 0xFF).toByte()
        }
    }

    /** 比较两块区域是否逐字节相等。 */
    fun regionEquals(data: ByteArray, offset: Int, pattern: ByteArray): Boolean {
        if (offset < 0 || offset + pattern.size > data.size) return false
        for (i in pattern.indices) {
            if (data[offset + i] != pattern[i]) return false
        }
        return true
    }
}
