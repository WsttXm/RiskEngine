plugins {
    alias(libs.plugins.android.application)
}

android {
    namespace = "com.wsttxm.riskenginesdk.demo"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.wsttxm.riskenginesdk.demo"
        minSdk = 30
        targetSdk = 36
        versionCode = 1
        versionName = "1.0"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
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
}

dependencies {
    implementation(project(":riskengine-sdk"))
    implementation(libs.appcompat)
    implementation(libs.material)
    implementation(libs.gson)
}
