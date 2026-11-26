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
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
}

dependencies {
    // Deliberately consume the produced release AAR binary rather than project(":riskengine-sdk").
    implementation(
        files(layout.projectDirectory.file("../riskengine-sdk/build/outputs/aar/riskengine-sdk-release.aar")) {
            builtBy(":riskengine-sdk:assembleRelease")
        }
    )

    // Pin AndroidX Test >= monitor 1.7.x for API 34/36 targetSdk=36 BroadcastReceiver flag compliance.
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    androidTestImplementation("androidx.test:core:1.6.1")
    androidTestImplementation("androidx.test:runner:1.6.2")
    androidTestImplementation("androidx.test:monitor:1.7.2")
    androidTestImplementation("androidx.test.espresso:espresso-core:3.6.1")
}

tasks.named("preBuild") {
    dependsOn(":riskengine-sdk:assembleRelease")
}

tasks.configureEach {
    if (name == "preDebugAndroidTestBuild") {
        dependsOn(":riskengine-sdk:assembleRelease")
    }
}
