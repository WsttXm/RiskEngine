plugins {
    alias(libs.plugins.android.application)
}

val releaseVersionName = providers.gradleProperty("releaseVersionName")
    .orElse(providers.gradleProperty("riskEngineVersion"))
val releaseVersionCode = providers.gradleProperty("releaseVersionCode").map(String::toInt).orElse(1)
val androidCompileSdk = providers.gradleProperty("androidCompileSdk").map(String::toInt).get()
val androidMinSdk = providers.gradleProperty("androidMinSdk").map(String::toInt).get()
val androidTargetSdk = providers.gradleProperty("androidTargetSdk").map(String::toInt).get()
val androidBuildToolsVersion = providers.gradleProperty("androidBuildToolsVersion").get()

android {
    namespace = "com.wsttxm.riskenginesdk.demo"
    compileSdk = androidCompileSdk
    buildToolsVersion = androidBuildToolsVersion

    defaultConfig {
        applicationId = "com.wsttxm.riskenginesdk.demo"
        minSdk = androidMinSdk
        targetSdk = androidTargetSdk
        versionCode = releaseVersionCode.get()
        versionName = releaseVersionName.get()
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }

    buildFeatures {
        buildConfig = true
    }
}

dependencies {
    implementation(project(":riskengine-sdk"))
    implementation(libs.appcompat)
    implementation(libs.material)
}
