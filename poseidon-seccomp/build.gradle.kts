plugins {
    // AGP 9 provides built-in Kotlin compilation (same as :app), so no kotlin.android.
    alias(libs.plugins.android.library)
}

android {
    namespace = "tech.ssemaj.poseidon.seccomp"
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
    // Transitively brings in :poseidon-core (JVM pipeline) and libposeidon_shim.so.
    // This module is the opt-in tier for Go/raw-syscall egress coverage via the
    // seccomp gate (controlled by the policy's nativeDnsCorrelation flag).
    api(project(":poseidon-native"))
}
