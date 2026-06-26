plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
    id("tech.ssemaj.poseidon") version "0.1.1"
}

android {
    namespace = "tech.ssemaj.poseidon"
    compileSdk {
        version = release(37)
    }

    defaultConfig {
        applicationId = "tech.ssemaj.poseidon"
        minSdk = 24
        targetSdk = 36
        versionCode = 1
        versionName = "1.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        ndk { abiFilters += "arm64-v8a" }
    }

    buildTypes {
        release {
            // Demo APK: sign with the debug key so the attached release artifact is installable.
            signingConfig = signingConfigs.getByName("debug")
            optimization {
                enable = false
            }
        }
        debug {
            // Exercise R8 on debug (keeps debug signing) to verify Poseidon survives shrinking.
            optimization {
                enable = true
            }
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
    buildFeatures {
        compose = true
    }
}

poseidon {
    // policyXml (default: src/main/res/xml/poseidon_policy.xml) is the canonical source.
    // Use DSL fields below only as an escape hatch (e.g. adding extra hosts or overriding mode
    // without touching the XML resource).
    nativeDnsCorrelation = true // opt in to Go/raw-syscall DNS correlation (costly; demo)
    // proposalsAction = "error"  // uncomment in CI to fail on unapproved library proposals
    // This app depends on :poseidon-all (includes libposeidon_shim.so), so enable ELF injection
    // so that native-SDK (libc) traffic — e.g. libcronet — is also host-enforced.
    injectNative = true
}

dependencies {
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.compose.material3)
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.ui.graphics)
    implementation(libs.androidx.compose.ui.tooling.preview)
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    // Poseidon: all-umbrella (core + native shim + seccomp) — consumed from the published
    // JitPack release to dogfood the real artifact rather than the local module.
    implementation(libs.poseidon.all)
    implementation(libs.cronet.embedded)
    implementation(libs.volley)
    // OkHttp present so the plugin's bytecode transform has something to instrument.
    implementation(libs.okhttp)
    testImplementation(libs.junit)
    androidTestImplementation(platform(libs.androidx.compose.bom))
    androidTestImplementation(libs.androidx.compose.ui.test.junit4)
    androidTestImplementation(libs.androidx.espresso.core)
    androidTestImplementation(libs.androidx.junit)
    debugImplementation(libs.androidx.compose.ui.test.manifest)
    debugImplementation(libs.androidx.compose.ui.tooling)
}