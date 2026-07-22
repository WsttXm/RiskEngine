plugins {
    alias(libs.plugins.android.application)
}

val releaseVersionName = providers.gradleProperty("releaseVersionName")
    .orElse(providers.gradleProperty("riskEngineVersion"))
val releaseVersionCode = providers.gradleProperty("releaseVersionCode").map(String::toInt).orElse(1)

android {
    namespace = "com.wsttxm.riskenginesdk.demo"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.wsttxm.riskenginesdk.demo"
        minSdk = 30
        targetSdk = 36
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
