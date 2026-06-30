plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
    id("tech.ssemaj.poseidon") version "0.1.2"
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
    // injectNative + nativeDnsCorrelation are ON by default, so native (libc/Cronet) and
    // Go/raw-syscall traffic are host-enforced with no config here — this block is left to
    // document the escape hatches.
    // proposalsAction = "error"  // uncomment in CI to fail on unapproved library proposals
}

dependencies {
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.navigation3.runtime)
    implementation(libs.androidx.navigation3.ui)
    implementation(libs.androidx.lifecycle.viewmodel.navigation3)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(libs.androidx.compose.material3)
    implementation(libs.androidx.compose.material.icons.extended)
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.ui.graphics)
    implementation(libs.androidx.compose.ui.tooling.preview)
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    // Poseidon: all-umbrella (core + native shim + seccomp) — consumed from the published
    // 0.1.3 release (includes strict raw default-deny + IPv6 raw helpers + TSYNC full
    // thread coverage) to dogfood the real artifact rather than the local module.
    implementation(libs.poseidon.all)
    implementation(libs.cronet.embedded)
    implementation(libs.volley)
    // OkHttp present so the plugin's bytecode transform has something to instrument.
    implementation(libs.okhttp)
    // MMKV (Tencent) ships a third-party native lib (libmmkv.so) and makes NO network
    // calls — used as a robustness probe that Poseidon's DT_NEEDED injection into a
    // dependency-provided .so leaves it loadable and runnable (and emits zero egress).
    implementation(libs.mmkv)
    // gRPC over Cronet's NATIVE transport: a real networking SDK whose bytes leave the
    // process through native code, so only Poseidon's native libc shim (not the JVM
    // adapters) can block it. cronet-api is excluded because cronet-embedded provides it.
    implementation(libs.grpc.cronet) {
        exclude(group = "org.chromium.net", module = "cronet-api")
    }
    implementation(libs.grpc.stub)
    testImplementation(libs.junit)
    androidTestImplementation(platform(libs.androidx.compose.bom))
    androidTestImplementation(libs.androidx.compose.ui.test.junit4)
    androidTestImplementation(libs.androidx.espresso.core)
    androidTestImplementation(libs.androidx.junit)
    debugImplementation(libs.androidx.compose.ui.test.manifest)
    debugImplementation(libs.androidx.compose.ui.tooling)
}