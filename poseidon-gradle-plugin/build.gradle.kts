plugins {
    `java-gradle-plugin`
    `kotlin-dsl`
    `maven-publish`
}

group = "tech.ssemaj.poseidon"
version = "0.1.0"

dependencies {
    // AGP Instrumentation API (provided by the consuming build at runtime).
    compileOnly("com.android.tools.build:gradle-api:9.2.1")
    compileOnly("org.ow2.asm:asm:9.7")
    compileOnly("org.ow2.asm:asm-commons:9.7")
    // YAML policy parsing (bundled with the plugin).
    implementation("org.yaml:snakeyaml:2.2")
}

gradlePlugin {
    plugins {
        create("poseidon") {
            id = "tech.ssemaj.poseidon"
            implementationClass = "tech.ssemaj.poseidon.gradle.PoseidonPlugin"
        }
    }
}
