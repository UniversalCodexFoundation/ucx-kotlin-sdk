// build.gradle.kts —— Unicodex UCX 阅读器 SDK（Kotlin / JVM）的 Gradle 构建脚本。
//
// 该 SDK 是一个【只读阅读器】：parse(解析) + integrity(BLAKE3 完整性) +
// verify(Ed25519 双层签名验证) + decrypt(UCXE 直接密钥 & 口令解密)。
// 不实现写入 / 签名 / 加密。
//
// 复用 JVM 生态：
//   - java.util.zip ：ZIP 容器读取（标准库，无需依赖）
//   - kotlinx.serialization ：codex.json / struct.json / expected.json 的 JSON 解析
//   - BouncyCastle ：BLAKE3、Ed25519、Argon2id、ChaCha20-Poly1305、X.509/PEM
//   - JCE（JDK 内置）：AES-GCM、AES-CBC、HMAC-SHA256、PBKDF2
//
// 许可证：MIT（与父项目 Unicodex 一致）。

plugins {
    // Kotlin/JVM 插件——提供 Kotlin 编译能力。
    kotlin("jvm") version "2.0.21"
    // kotlinx.serialization 编译器插件——为 @Serializable 数据类生成序列化代码。
    kotlin("plugin.serialization") version "2.0.21"
}

// Maven 坐标（§2：Kotlin 包/命名空间 = org.unicodex.ucx）。
group = "org.unicodex.ucx"
version = "0.4.0"

repositories {
    // 从 Maven Central 拉取依赖。
    mavenCentral()
}

dependencies {
    // ---- 运行时依赖 ----
    // kotlinx.serialization JSON：宽松反序列化（忽略未知字段，符合 SDK-API §1 设计原则 2）。
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.7.3")
    // BouncyCastle Provider：提供 BLAKE3、Ed25519、Argon2id、ChaCha20-Poly1305 等。
    // 使用 jdk18on 构建（适配 JDK 17+，本机为 JDK 21）。
    implementation("org.bouncycastle:bcprov-jdk18on:1.78.1")
    // BouncyCastle PKIX：X.509 证书 / PEM 解析辅助。
    implementation("org.bouncycastle:bcpkix-jdk18on:1.78.1")

    // ---- 测试依赖 ----
    // JUnit 5（Jupiter）：一致性测试 T1–T10。
    testImplementation("org.junit.jupiter:junit-jupiter:5.10.2")
    testImplementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.7.3")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

kotlin {
    // 目标 JVM 17（向后兼容）。这里用 compilerOptions 直接指定 -jvm-target，
    // 而非 jvmToolchain(N)，以避免 Gradle 在缺少对应 JDK 时尝试下载 toolchain。
    // 本机以 JDK 21 运行构建即可生成 JVM 17 字节码。
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}

java {
    // 同样为 Java 编译指定源/目标兼容级别 17（测试中无 .java 文件，但保持一致）。
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

tasks.test {
    // 使用 JUnit 5 平台运行测试。
    useJUnitPlatform()
    // 在控制台显示每个测试的通过 / 失败 / 跳过情况。
    testLogging {
        events("passed", "failed", "skipped")
        showStandardStreams = true
    }
}
