plugins {
    // AGP 9 provides built-in Kotlin compilation (same as :app), so no kotlin.android.
    alias(libs.plugins.android.library)
}

android {
    namespace = "tech.ssemaj.poseidon.all"
    compileSdk {
        version = release(37)
    }

    defaultConfig {
        minSdk = 24
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
}

dependencies {
    // Umbrella: expose all three Poseidon tiers transitively.
    api(project(":poseidon-core"))
    api(project(":poseidon-native"))
    api(project(":poseidon-seccomp"))
}
