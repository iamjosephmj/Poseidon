plugins {
    `java-gradle-plugin`
    `kotlin-dsl`
    `maven-publish`
}

group = "tech.ssemaj.poseidon"
version = "0.1.4"

// Target Java 17 bytecode so the published plugin loads on any Gradle JDK (17+), regardless
// of the JDK used to build it. Both Java AND Kotlin targets must be pinned (the plugin code
// is Kotlin), else compiling under a newer JDK emits class files that older Gradle JVMs
// (which run the consuming build) can't load.
java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}
tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile>().configureEach {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}

dependencies {
    // AGP Instrumentation API (provided by the consuming build at runtime).
    compileOnly("com.android.tools.build:gradle-api:9.2.1")
    compileOnly("org.ow2.asm:asm:9.7")
    compileOnly("org.ow2.asm:asm-commons:9.7")
    // YAML policy parsing (bundled with the plugin).
    implementation("org.yaml:snakeyaml:2.2")
    // JUnit for testing.
    testImplementation("junit:junit:4.13.2")
}

gradlePlugin {
    plugins {
        create("poseidon") {
            id = "tech.ssemaj.poseidon"
            implementationClass = "tech.ssemaj.poseidon.gradle.PoseidonPlugin"
        }
    }
}
