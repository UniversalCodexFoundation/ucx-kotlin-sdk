/*
 * SPDX-License-Identifier: MIT
 *
 * CertUtil.kt —— X.509 证书 / Ed25519 / PEM 辅助（UCX-FORMAT §6.3）。
 *
 * 仅需：
 *   - 解析 DER 证书，读取 subjectPublicKeyInfo 中的 32 字节 raw Ed25519 公钥（OID 1.3.101.112）。
 *   - 读取 validity（notBefore/notAfter）并与当前时间比较。
 *   - 读取 subject CN 与 issuer CN（判定 self-signed / ca-issued）。
 *   - Ed25519 验签（对原始消息字节）。
 *   - PEM(CERTIFICATE) 解码为 DER。
 *
 * 不做 CA 链 / 路径校验（参考验证器不做），信任策略交由应用层。
 */

package org.unicodex.ucx

import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.x500.RDN
import org.bouncycastle.asn1.x500.style.BCStyle
import org.bouncycastle.asn1.x500.style.IETFUtils
import org.bouncycastle.asn1.x509.Certificate
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import java.util.Date

/** 从 DER 证书提取出的精简信息。 */
internal class ParsedCert(
    /** 原始 DER 字节。 */
    val der: ByteArray,
    /** 32 字节 raw Ed25519 公钥。 */
    val publicKey: ByteArray,
    /** subject CN（可能为 null）。 */
    val subjectCn: String?,
    /** issuer CN（可能为 null）。 */
    val issuerCn: String?,
    /** 有效期起。 */
    val notBefore: Date,
    /** 有效期止。 */
    val notAfter: Date,
) {
    /** 在给定时刻是否有效（notBefore ≤ now ≤ notAfter）。 */
    fun isTimeValid(now: Date = Date()): Boolean =
        !now.before(notBefore) && !now.after(notAfter)

    /** self-signed 判定：subjectCN == issuerCN（§6.3）。 */
    fun certType(): String =
        if (subjectCn != null && subjectCn == issuerCn) "self-signed" else "ca-issued"

    /** lowercase-hex BLAKE3(cert_der)，64 hex（§6.3）。 */
    fun fingerprint(): String =
        Hashing.blake3(der).joinToString("") { "%02x".format(it.toInt() and 0xFF) }
}

internal object CertUtil {

    private val ED25519_OID = ASN1ObjectIdentifier(UcxConstants.ED25519_SPKI_OID)

    /**
     * 解析 DER 证书。要求 SPKI 算法为 Ed25519（1.3.101.112），公钥恰好 32 字节。
     * @throws Exception 解析失败 / 非 Ed25519。
     */
    fun parseDer(der: ByteArray): ParsedCert {
        val cert = Certificate.getInstance(der)
        val spki: SubjectPublicKeyInfo = cert.subjectPublicKeyInfo
        if (spki.algorithm.algorithm != ED25519_OID) {
            throw IllegalStateException("certificate SPKI is not Ed25519")
        }
        // subjectPublicKey 的 BIT STRING 内容即 32 字节 raw 公钥。
        val pub = spki.publicKeyData.bytes
        if (pub.size != UcxConstants.ED25519_PUBKEY_LEN) {
            throw IllegalStateException("Ed25519 public key must be 32 bytes")
        }
        val subjectCn = cnOf(cert, subject = true)
        val issuerCn = cnOf(cert, subject = false)
        val notBefore = cert.startDate.date
        val notAfter = cert.endDate.date
        return ParsedCert(der, pub, subjectCn, issuerCn, notBefore, notAfter)
    }

    /** 提取 subject 或 issuer 的 CN（commonName），无则 null。 */
    private fun cnOf(cert: Certificate, subject: Boolean): String? {
        val name = if (subject) cert.subject else cert.issuer
        val rdns: Array<RDN> = name.getRDNs(BCStyle.CN)
        if (rdns.isEmpty()) return null
        val first = rdns[0].first ?: return null
        return IETFUtils.valueToString(first.value)
    }

    /**
     * Ed25519 验签：用 32 字节 raw 公钥验证 message 上的 64 字节 signature。
     * @return true 验签通过。
     */
    fun verifyEd25519(publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean {
        if (publicKey.size != UcxConstants.ED25519_PUBKEY_LEN) return false
        if (signature.size != UcxConstants.ED25519_SIG_LEN) return false
        return try {
            val params = Ed25519PublicKeyParameters(publicKey, 0)
            val signer = Ed25519Signer()
            signer.init(false, params)
            signer.update(message, 0, message.size)
            signer.verifySignature(signature)
        } catch (e: Exception) {
            false
        }
    }

    /**
     * 将 PEM(CERTIFICATE) 文本解码为 DER 字节。要求 PEM label 为 "CERTIFICATE"（§6.1 步骤 5）。
     * @throws Exception label 不符或解码失败。
     */
    fun pemCertToDer(pem: String): ByteArray {
        val begin = "-----BEGIN CERTIFICATE-----"
        val end = "-----END CERTIFICATE-----"
        val beginIdx = pem.indexOf(begin)
        val endIdx = pem.indexOf(end)
        if (beginIdx < 0 || endIdx < 0 || endIdx < beginIdx) {
            throw IllegalStateException("PEM does not contain a CERTIFICATE block")
        }
        val body = pem.substring(beginIdx + begin.length, endIdx)
            .replace("\r", "")
            .replace("\n", "")
            .replace(" ", "")
        return Hashing.base64Decode(body)
    }
}
