plugins {
    alias(libs.plugins.android.application)
}

android {
    namespace = "com.wsttxm.riskenginesdk.integrationtest"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.wsttxm.riskenginesdk.integrationtest"
        minSdk = 30
        targetSdk = 36
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
