English | [中文](README.md)

# Unicodex UCX SDK -- Kotlin / JVM

> A **read-only reader** SDK for the unified standard novel file format `.ucx` (Kotlin / JVM implementation).
> Provides: parsing (parse) + integrity verification (integrity, BLAKE3) + dual-layer signature verification (verify, Ed25519) + UCXE decryption (decrypt).
> **Does not include** writing / signing / encryption.

This SDK follows [`sdk/UCX-FORMAT.md`](../UCX-FORMAT.md) (byte-level wire-format) and [`sdk/SDK-API.md`](../SDK-API.md) (cross-language unified API contract).

- Package / Namespace: `org.unicodex.ucx`
- License: **MIT**
- Capability Level: **L3 (full-featured)**

---

## Installation

This SDK is built with Gradle (Kotlin DSL) and depends on the JVM ecosystem:

| Purpose | Dependency |
|---------|------------|
| ZIP container reading | `java.util.zip` (JDK built-in) |
| JSON parsing | `org.jetbrains.kotlinx:kotlinx-serialization-json` |
| BLAKE3 / Ed25519 / Argon2id / ChaCha20-Poly1305 / X.509 | `org.bouncycastle:bcprov-jdk18on`, `bcpkix-jdk18on` |
| AES-GCM / AES-CBC / HMAC-SHA256 / PBKDF2 | JCE (JDK built-in) |

Add the following to your `build.gradle.kts` (once published):

```kotlin
dependencies {
    implementation("org.unicodex.ucx:unicodex-ucx:0.4.0")
}
```

Requires JDK 17+ (development and testing were done on JDK 21).

---

## Usage Examples

```kotlin
import org.unicodex.ucx.*

// 1) Open an archive (verify ZIP magic@0 + mimetype, and parse codex/struct/manifest)
val archive = UcxArchive.open("sample.ucx")
// Or from in-memory bytes: UcxArchive.openBytes(bytes)

// 2) Metadata and table of contents
println(archive.codex.title.main)          // "Sample Novel"
println(archive.codex.language)            // "en"
for (ch in archive.chapters()) {
    println("${ch.title} -> ${ch.path}")    // "Chapter 1 -> content/chapter-001.md"
}

// 3) Read a chapter (plaintext)
val text = archive.readChapterText("chapter-001.md")

// 4) Integrity verification (BLAKE3 vs MANIFEST, Base64 comparison)
val integrity = archive.verifyIntegrity()
println(integrity.valid)                    // true

// 5) Signature verification (Layer1 SF/EC + Layer2 signature block, both Ed25519)
val sig = UcxArchive.open("sample-signed.ucx").verifySignatures()
println(sig.status)                         // VERIFIED
println(sig.signers.first().fingerprint)    // c7eda2f7...

// 6) Decrypt UCXE (module-level functions)
val key = java.util.Base64.getDecoder()
    .decode("MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=")     // 32 bytes
val plain1 = decryptWithKey(File("plain-aesgcm.ucxe").readBytes(), key)
val plain2 = decryptWithPassphrase(File("plain-pass.ucxe").readBytes(), "sdktest-passphrase")

// 7) Capability query
println(capabilities())
```

UCXE detection:

```kotlin
if (isUcxe(bytes)) { /* This is an encrypted chapter */ }
// Or: archive.isChapterEncrypted("chapter-001.md")
```

---

## Capability Matrix (`capabilities()`)

| Capability | Status | Description |
|------------|--------|-------------|
| `parse` | true | ZIP + JSON + container validation |
| `integrity` | true | BLAKE3 (BouncyCastle `Blake3Digest`) |
| `verifySignatures` | true | Ed25519 dual-layer (Layer1 SF/EC + Layer2 signature block) |
| `decryptDirectKey` | true | KDF=None; GCM / ChaCha20 |
| `decryptPassphrase` | true | NFC -> KDF -> AEAD/CBC |
| `algorithms` | `AES-256-GCM`, `AES-256-CBC`, `ChaCha20-Poly1305` | GCM/CBC via JCE; ChaCha20-Poly1305 via BouncyCastle |
| `kdfs` | `argon2id`, `pbkdf2` | Argon2id via BouncyCastle; PBKDF2-HMAC-SHA256 via JCE |

This SDK achieves **L3 (full-featured)**.

---

## Quantized Constants

All SDK-API.md section 6 constants are exposed via `UcxConstants`, for example:

```kotlin
UcxConstants.MIMETYPE                 // "application/vnd.unicodex+zip"
UcxConstants.UCXE_MAGIC              // [0x55,0x43,0x58,0x45]
UcxConstants.ALGO_AES_256_GCM       // 0x01
UcxConstants.ARGON2_DEFAULT_MEM_KIB // 65536
UcxConstants.L2_BLOCK_MAGIC         // "UCX Sig Block 1\0"
```

---

## Error Model

Public API failures throw subclasses of `UcxException` (SDK-API.md section 5):

| Exception | Trigger |
|-----------|---------|
| `InvalidFormatException` | Not a ZIP, mimetype mismatch, UCX MAJOR>1, UCXE magic/version invalid |
| `NotFoundException` | Requested entry / chapter does not exist |
| `ParseException` | JSON / MANIFEST parsing failure |
| `UnsupportedException` | Unimplemented algorithm / KDF / capability |
| `DecryptionException` | Any decryption failure (**opaque**: unified message, no cause attached, to prevent oracle attacks) |
| `UcxIoException` | File read/write failure |

---

## Testing

Conformance tests T1-T10 (SDK-API.md section 8) are located in `src/test/kotlin/`, with assertions taken from `testdata/expected.json`.

```bash
gradle test
```

Fixtures are self-contained in `testdata/` (also copied to `src/test/resources/testdata/` for test classpath loading), facilitating independent open-source usage.

---

## Limitations

- **Read-only**: Does not implement writing / signing / encryption (consistent with the project scope).
- **Ed25519 signatures only**: Consistent with the reference implementation; RSA/ECDSA are not implemented (and the format does not use them).
- **Chunked decryption path** is implemented (section 7.7), but fixtures are all small files (< 64 MiB). The chunked path is not covered by conformance fixtures and relies solely on code logic for correctness (base[0..8] || u32_be(idx) sub-nonce, per-chunk tag, file-level AAD).
- **X.509 trust policy**: Consistent with the reference verifier -- only reads the SPKI public key and validity window; does not perform CA chain / path validation. Trust policy is delegated to the application layer.
- **PBKDF2 passphrase bytes**: The JDK's `PBKDF2WithHmacSHA256` encodes characters as UTF-8. This SDK performs NFC normalization on the passphrase before derivation, consistent with the reference implementation. Current conformance fixtures only cover the Argon2id passphrase mode; the PBKDF2 path is not covered by fixtures.

---

## Design Trade-offs

- BLAKE3 and Argon2id are called directly via the **BouncyCastle lightweight API** (`Blake3Digest` / `Argon2BytesGenerator`), without registering a JCE Provider.
- ChaCha20-Poly1305 uses the BouncyCastle `ChaCha20Poly1305` engine (although JCE has ChaCha20-Poly1305 since JDK 11, the BC engine is chosen to unify AAD handling and cross-JDK behavior).
- AES-GCM / AES-CBC / HMAC-SHA256 / PBKDF2 use **JCE** (JDK built-in) for optimal performance and availability.
- Layer 2 signature block location and protected content reconstruction operate directly on **raw disk bytes** (`ZipReader.rawBytes`); all other parsing / integrity / decryption operations work on **decompressed bytes**.

---

## Versioning

This SDK uses `X.Y.Z` version numbers (see project ADR-012):
- **`X.Y`** (first two digits) = the supported **UCX standard version** (major.minor). **Same first two digits implies support for the same UCX standard and identical public API**.
- **`Z`** (last digit) = the SDK's own patch number (bug fixes only, no public API changes).

The current version **0.4.0** corresponds to UCX standard **0.4.x**. When the UCX standard upgrades to the next minor version (e.g., 0.5), a new SDK line (0.5.x) will be created, while the old standard line (0.4.x) **continues to receive patches and will not be deprecated** (similar to how Python maintains multiple version series in parallel).
