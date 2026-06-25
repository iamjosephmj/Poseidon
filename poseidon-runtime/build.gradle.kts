plugins {
    // AGP 9 provides built-in Kotlin compilation (same as :app), so no kotlin.android.
    alias(libs.plugins.android.library)
}

android {
    namespace = "tech.ssemaj.poseidon.runtime"
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

    testOptions {
        unitTests {
            isIncludeAndroidResources = true
            isReturnDefaultValues = true
        }
    }
}

dependencies {
    // Client types are referenced only by the injected adapters; compileOnly so they
    // are never forced into a consuming app that doesn't already use them.
    compileOnly("com.squareup.okhttp3:okhttp:4.12.0")
    compileOnly("com.android.volley:volley:1.2.1")
    compileOnly("org.chromium.net:cronet-embedded:143.7445.0")
    // Auto-loads the compiled policy asset at process start.
    implementation("androidx.startup:startup-runtime:1.1.1")
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.robolectric:robolectric:4.13")
    testImplementation("androidx.test:core:1.6.1")
}
