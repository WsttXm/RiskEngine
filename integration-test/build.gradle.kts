plugins {
    alias(libs.plugins.android.application)
}

val androidCompileSdk = providers.gradleProperty("androidCompileSdk").map(String::toInt).get()
val androidMinSdk = providers.gradleProperty("androidMinSdk").map(String::toInt).get()
val androidTargetSdk = providers.gradleProperty("androidTargetSdk").map(String::toInt).get()
val androidBuildToolsVersion = providers.gradleProperty("androidBuildToolsVersion").get()

android {
    namespace = "com.wsttxm.riskenginesdk.integrationtest"
    compileSdk = androidCompileSdk
    buildToolsVersion = androidBuildToolsVersion

    defaultConfig {
        applicationId = "com.wsttxm.riskenginesdk.integrationtest"
        minSdk = androidMinSdk
        targetSdk = androidTargetSdk
        versionCode = 1
        versionName = "1.0"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
}

dependencies {
    // Deliberately consume the produced binary rather than project(":riskengine-sdk").
    implementation(files("../riskengine-sdk/build/outputs/aar/riskengine-sdk-release.aar"))
}

tasks.named("preBuild") {
    dependsOn(":riskengine-sdk:assembleRelease")
}
