plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
    id("tech.ssemaj.poseidon") version "0.1.0"
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
    // Poseidon: all-umbrella brings core + native shim + seccomp tier.
    implementation(project(":poseidon-all"))
    implementation("org.chromium.net:cronet-embedded:143.7445.0")
    implementation("com.android.volley:volley:1.2.1")
    // OkHttp present so the plugin's bytecode transform has something to instrument.
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
    testImplementation(libs.junit)
    androidTestImplementation(platform(libs.androidx.compose.bom))
    androidTestImplementation(libs.androidx.compose.ui.test.junit4)
    androidTestImplementation(libs.androidx.espresso.core)
    androidTestImplementation(libs.androidx.junit)
    debugImplementation(libs.androidx.compose.ui.test.manifest)
    debugImplementation(libs.androidx.compose.ui.tooling)
}