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
    compileOnly(libs.okhttp)
    compileOnly(libs.volley)
    compileOnly(libs.cronet.embedded)
    // Auto-loads the compiled policy asset at process start.
    implementation(libs.androidx.startup.runtime)
    testImplementation(libs.junit)
    testImplementation(libs.robolectric)
    testImplementation(libs.androidx.test.core)
}
