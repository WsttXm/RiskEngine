plugins {
    alias(libs.plugins.android.library)
    id("maven-publish")
}

val releaseVersionName = providers.gradleProperty("releaseVersionName")
    .orElse(providers.gradleProperty("riskEngineVersion"))
version = releaseVersionName.get()
group = "com.wsttxm"

android {
    namespace = "com.wsttxm.riskenginesdk"
    compileSdk = 36

    defaultConfig {
        minSdk = 30

        buildConfigField("String", "SDK_VERSION", "\"${releaseVersionName.get()}\"")

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        consumerProguardFiles("consumer-rules.pro")

        externalNativeBuild {
            cmake {
                cppFlags += "-std=c++17 -fvisibility=hidden -fvisibility-inlines-hidden"
                arguments += "-DANDROID_STL=c++_static"
            }
        }

        ndk {
            abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86_64", "x86")
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
            // An SDK AAR is consumed and optimized again by the host application.
            // Minifying here can remove public nested types before consumers compile.
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

    buildFeatures {
        buildConfig = true
    }

    publishing {
        singleVariant("release") {
            withSourcesJar()
        }
    }
}

afterEvaluate {
    publishing {
        publications {
            create<MavenPublication>("release") {
                from(components["release"])
                groupId = project.group.toString()
                artifactId = "riskengine-sdk"
                version = project.version.toString()
                pom {
                    name.set("RiskEngine Android SDK")
                    description.set("On-device Android security risk signal SDK")
                }
            }
        }
    }
}

dependencies {
    testImplementation(libs.junit)
    testImplementation(libs.json)
    androidTestImplementation(libs.ext.junit)
    androidTestImplementation(libs.espresso.core)
}
