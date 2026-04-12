plugins {
    alias(libs.plugins.android.library)
}

android {
    namespace = "com.wsttxm.riskenginesdk"
    compileSdk = 36

    defaultConfig {
        minSdk = 30

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        consumerProguardFiles("consumer-rules.pro")

        externalNativeBuild {
            cmake {
                cppFlags += "-std=c++17 -fvisibility=hidden"
                arguments += "-DANDROID_STL=c++_static"
            }
        }

        ndk {
            abiFilters += listOf("arm64-v8a", "armeabi-v7a")
        }
    }

    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            version = "3.22.1"
        }
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

    @Suppress("UnstableApiUsage")
    testOptions {
        unitTests.all {
            it.enabled = it.name != "testReleaseUnitTest"
        }
    }
}

dependencies {
    implementation(libs.gson)
    implementation(libs.okhttp)
    implementation(libs.hidden.api.bypass)
    implementation(libs.appcompat)

    testImplementation(libs.junit)
    androidTestImplementation(libs.ext.junit)
    androidTestImplementation(libs.espresso.core)
}
