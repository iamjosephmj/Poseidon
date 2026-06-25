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
include(":app")
include(":poseidon-runtime")
include(":poseidon-core")
include(":poseidon-native")
include(":poseidon-seccomp")
include(":poseidon-all")
