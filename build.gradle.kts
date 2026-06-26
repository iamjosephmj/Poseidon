// Top-level build file where you can add configuration options common to all sub-projects/modules.
plugins {
    alias(libs.plugins.android.application) apply false
    alias(libs.plugins.android.library) apply false
    alias(libs.plugins.kotlin.android) apply false
    alias(libs.plugins.kotlin.compose) apply false
}

// JitPack coordinates → com.github.iamjosephmj.Poseidon:<module>:<tag>
allprojects {
    group = "com.github.iamjosephmj.Poseidon"
    version = "0.1.2"
}

// Publish the poseidon-* Android library modules as AARs (consumed via JitPack).
subprojects {
    plugins.withId("com.android.library") {
        if (name.startsWith("poseidon-")) {
            apply(plugin = "maven-publish")
            extensions.configure<com.android.build.api.dsl.LibraryExtension> {
                publishing { singleVariant("release") }
            }
            afterEvaluate {
                extensions.configure<PublishingExtension> {
                    publications {
                        register<MavenPublication>("release") {
                            from(components["release"])
                        }
                    }
                }
            }
        }
    }
}