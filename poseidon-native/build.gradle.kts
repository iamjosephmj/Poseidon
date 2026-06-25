plugins {
    // AGP 9 provides built-in Kotlin compilation (same as :app), so no kotlin.android.
    alias(libs.plugins.android.library)
}

android {
    namespace = "tech.ssemaj.poseidon.nativeshim"
    compileSdk {
        version = release(37)
    }

    defaultConfig {
        minSdk = 24
        // Keep rules shipped to consumers so enabling R8 doesn't break Poseidon.
        consumerProguardFiles("consumer-rules.pro")
        // Poseidon ships the shim for every ABI it can guard.
        ndk {
            abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86", "x86_64")
        }
        externalNativeBuild {
            cmake {
                arguments += "-DANDROID_STL=none"
            }
        }
    }

    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
}

dependencies {
    implementation(project(":poseidon-core"))
}
