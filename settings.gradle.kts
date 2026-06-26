pluginManagement {
    // poseidon-gradle-plugin is published to mavenLocal (built standalone) and
    // resolved from there — avoids leaking the plugin build's Kotlin onto the
    // shared classpath that `includeBuild` in pluginManagement would cause.
    repositories {
        mavenLocal()
        google {
            content {
                includeGroupByRegex("com\\.android.*")
                includeGroupByRegex("com\\.google.*")
                includeGroupByRegex("androidx.*")
            }
        }
        mavenCentral()
        gradlePluginPortal()
    }
}
plugins {
    id("org.gradle.toolchains.foojay-resolver-convention") version "1.0.0"
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}
// (mavenLocal only needed for the plugin marker, declared in pluginManagement above)

rootProject.name = "Poseidon"

// Module -> AGP namespace -> source package map (read before renaming anything):
//   :poseidon-core    namespace tech.ssemaj.poseidon.runtime    package tech.ssemaj.poseidon.runtime
//   :poseidon-native  namespace tech.ssemaj.poseidon.nativeshim  package tech.ssemaj.poseidon.runtime
//   :poseidon-seccomp namespace tech.ssemaj.poseidon.seccomp     package tech.ssemaj.poseidon.seccomp
//   :poseidon-all     namespace tech.ssemaj.poseidon.all         package tech.ssemaj.poseidon.all
//   poseidon-gradle-plugin (standalone build)                    package tech.ssemaj.poseidon.gradle
// The runtime source package `tech.ssemaj.poseidon.runtime` is FROZEN — it is load-bearing for:
//   (a) JNI symbol names  Java_tech_ssemaj_poseidon_runtime_NativeShimBackend_*  (poseidon-native shim.c + poseidon.ver)
//   (b) the plugin's ASM bytecode-injection target FQNs        (PoseidonClassVisitorFactory string literals)
//   (c) consumer-rules.pro -keep rules                         (poseidon-core + poseidon-native)
//   (d) the manifest InitializationProvider meta-data          (tech.ssemaj.poseidon.runtime.PoseidonInitializer)
//   (e) the reflective Class.forName("...NativeShimBackend")   (PoseidonInitializer)
// :poseidon-native namespace is .nativeshim ON PURPOSE: it must differ from :poseidon-core's
// .runtime namespace (AGP forbids duplicate library namespaces), while the package stays .runtime (JNI).
include(":app")
include(":poseidon-core")
include(":poseidon-native")
include(":poseidon-seccomp")
include(":poseidon-all")
