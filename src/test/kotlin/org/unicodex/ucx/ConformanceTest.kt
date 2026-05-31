/*
 * SPDX-License-Identifier: MIT OR Apache-2.0
 *
 * ConformanceTest.kt —— SDK-API.md §8 一致性测试 T1–T10。
 *
 * 所有断言取自 testdata/expected.json，夹具为 src/test/resources/testdata 下的本地副本。
 * 验证 parse / integrity / verifySignatures / decrypt 的跨语言一致性。
 */

package org.unicodex.ucx

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.util.Base64

class ConformanceTest {

    // ---- 夹具加载工具 ----

    private fun fixture(name: String): ByteArray {
        val stream = javaClass.classLoader.getResourceAsStream("testdata/$name")
            ?: error("fixture not found on classpath: testdata/$name")
        return stream.use { it.readBytes() }
    }

    private val expected: JsonObject by lazy {
        Json { ignoreUnknownKeys = true }
            .parseToJsonElement(fixture("expected.json").toString(Charsets.UTF_8))
            .jsonObject
    }

    private fun openSample(): UcxArchive = UcxArchive.openBytes(fixture("sample.ucx"))

    // 期望明文（45 字节）。
    private val plaintext = "The quick brown fox jumps over the lazy dog.\n"

    // 直接密钥（base64）。
    private val directKey: ByteArray =
        Base64.getDecoder().decode("MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=")

    // =================================================================================
    // T1 —— codex 元数据
    // =================================================================================
    @Test
    fun t1_codexMetadata() {
        val codex = openSample().codex
        assertEquals("urn:ucx:fe944340-2d18-4346-ba19-f291e7b00604", codex.ucxId)
        assertEquals("Sample Novel", codex.title.main)
        assertEquals("UCX Team", codex.creators[0].name)
        assertEquals("author", codex.creators[0].role)
        assertEquals("en", codex.language)
    }

    // =================================================================================
    // T2 —— chapters() 扁平化
    // =================================================================================
    @Test
    fun t2_chapters() {
        val chapters = openSample().chapters()
        assertEquals(1, chapters.size)
        assertEquals("第一章", chapters[0].title)
        assertEquals("chapter-001.md", chapters[0].file)
        assertEquals("content/chapter-001.md", chapters[0].path)
    }

    // =================================================================================
    // T3 —— readChapterText
    // =================================================================================
    @Test
    fun t3_readChapterText() {
        val text = openSample().readChapterText("chapter-001.md")
        assertEquals("# Chapter One\n\nThe quick brown fox jumps over the lazy dog.\n", text)
    }

    // =================================================================================
    // T4 —— verifyIntegrity (sample.ucx)：3 条目全 valid，Base64 比对
    // =================================================================================
    @Test
    fun t4_verifyIntegrity() {
        val result = openSample().verifyIntegrity()
        assertTrue(result.valid, "integrity must be valid")
        assertEquals(3, result.entries.size)
        assertTrue(result.entries.all { it.valid })

        // 进一步比对 expected.json 中记录的 Base64 digest。
        val manifestEntries = expected["archive"]!!.jsonObject["manifest_entries"]!!.jsonArray
        for (e in manifestEntries) {
            val o = e.jsonObject
            val name = o["name"]!!.jsonPrimitive.content
            val digest = o["blake3_base64"]!!.jsonPrimitive.content
            val actual = result.entries.first { it.name == name }
            assertEquals(digest, actual.expected, "manifest digest for $name")
            assertEquals(digest, actual.actual, "recomputed digest for $name")
        }
    }

    // =================================================================================
    // T5 —— verifySignatures (sample-signed.ucx)：VERIFIED，双层有效
    // =================================================================================
    @Test
    fun t5_verifySignaturesSigned() {
        val archive = UcxArchive.openBytes(fixture("sample-signed.ucx"))
        val result = archive.verifySignatures()
        assertEquals(SignatureStatus.VERIFIED, result.status)
        assertTrue(result.layer1Present && result.layer1Valid, "layer1 valid")
        assertTrue(result.layer2Present && result.layer2Valid, "layer2 valid")
        val signer = result.signers.first { it.signerId == "AUTHOR" }
        assertEquals("UCX Sample Signer", signer.subjectCn)
        assertEquals(
            "c7eda2f7b775e395c583c220ff171a7b22c1c0ce3c887b9a3db3d74c944219d0",
            signer.fingerprint,
        )
        assertTrue(signer.layer1Valid)
        assertTrue(signer.layer2Valid)
        // (P1) 断言 certType 字段与 expected.json 一致：样本签名者使用自签名证书。
        assertEquals("self-signed", signer.certType,
            "signer certType must be 'self-signed' per expected.json")
    }

    // =================================================================================
    // T6 —— verifySignatures (sample.ucx)：UNSIGNED
    // =================================================================================
    @Test
    fun t6_verifySignaturesUnsigned() {
        val result = openSample().verifySignatures()
        assertEquals(SignatureStatus.UNSIGNED, result.status)
        assertFalse(result.layer1Present)
        assertFalse(result.layer2Present)
    }

    // =================================================================================
    // T7 —— decryptWithKey (AES-256-GCM, direct key)
    // =================================================================================
    @Test
    fun t7_decryptAesGcm() {
        val out = UcxeCrypto.decryptWithKey(fixture("plain-aesgcm.ucxe"), directKey)
        assertEquals(plaintext, out.toString(Charsets.UTF_8))
    }

    // =================================================================================
    // T8 —— decryptWithKey (ChaCha20-Poly1305, direct key)
    // =================================================================================
    @Test
    fun t8_decryptChaCha() {
        val out = UcxeCrypto.decryptWithKey(fixture("plain-chacha.ucxe"), directKey)
        assertEquals(plaintext, out.toString(Charsets.UTF_8))
    }

    // =================================================================================
    // T9 —— decryptWithPassphrase (AES-256-GCM, Argon2id)
    // =================================================================================
    @Test
    fun t9_decryptPassphrase() {
        val out = UcxeCrypto.decryptWithPassphrase(
            fixture("plain-pass.ucxe"),
            "sdktest-passphrase",
        )
        assertEquals(plaintext, out.toString(Charsets.UTF_8))
    }

    // =================================================================================
    // T10 —— 篡改密文 → DecryptionException
    // =================================================================================
    @Test
    fun t10_tamperRejected() {
        val tampered = fixture("plain-aesgcm.ucxe")
        // 翻转密文区域的某个字节（offset 40 落在密文中部）。
        tampered[40] = (tampered[40].toInt() xor 0xFF).toByte()
        assertThrows(DecryptionException::class.java) {
            UcxeCrypto.decryptWithKey(tampered, directKey)
        }
    }

    // =================================================================================
    // 附加：plaintext 字节与 plain.txt 夹具一致
    // =================================================================================
    @Test
    fun extra_plaintextMatchesFixture() {
        assertArrayEquals(plaintext.toByteArray(Charsets.UTF_8), fixture("plain.txt"))
    }

    // =================================================================================
    // 附加：capabilities() 声明
    // =================================================================================
    @Test
    fun extra_capabilities() {
        val caps = capabilities()
        assertTrue(caps.parse)
        assertTrue(caps.integrity)
        assertTrue(caps.verifySignatures)
        assertTrue(caps.decryptDirectKey)
        assertTrue(caps.decryptPassphrase)
        assertTrue(caps.algorithms.contains("AES-256-GCM"))
        assertTrue(caps.kdfs.contains("argon2id"))
    }
}
