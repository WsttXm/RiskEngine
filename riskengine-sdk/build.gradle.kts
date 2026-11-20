plugins {
    alias(libs.plugins.android.library)
    id("maven-publish")
}

val releaseVersionName = providers.gradleProperty("releaseVersionName")
    .orElse(providers.gradleProperty("riskEngineVersion"))
val androidCompileSdk = providers.gradleProperty("androidCompileSdk").map(String::toInt).get()
val androidMinSdk = providers.gradleProperty("androidMinSdk").map(String::toInt).get()
val androidBuildToolsVersion = providers.gradleProperty("androidBuildToolsVersion").get()
val androidCmakeVersion = providers.gradleProperty("androidCmakeVersion").get()
val androidNdkVersion = providers.gradleProperty("androidNdkVersion").get()
version = releaseVersionName.get()
group = "com.wsttxm"

android {
    namespace = "com.wsttxm.riskenginesdk"
    compileSdk = androidCompileSdk
    buildToolsVersion = androidBuildToolsVersion
    ndkVersion = androidNdkVersion

    defaultConfig {
        minSdk = androidMinSdk

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
            version = androidCmakeVersion
        }
    }

    buildTypes {
        release {
            // Host apps minify the AAR. Minifying here breaks release unit tests
            // and can strip nested public types before consumers compile.
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

abstract class GenerateDetectionListsTask : DefaultTask() {
    @get:InputFile
    abstract val iniFile: RegularFileProperty

    @get:OutputFile
    abstract val javaOutput: RegularFileProperty

    @get:OutputFile
    abstract val cppOutput: RegularFileProperty

    private fun mix(input: Int): Int {
        var value = input
        value = value xor (value shl 13)
        value = value xor (value ushr 17)
        value = value xor (value shl 5)
        return if (value == 0) 0x9E3779B9.toInt() else value
    }

    private fun encodeOne(seed: Int, plain: String): String {
        val raw = plain.toByteArray(Charsets.UTF_8)
        var state = mix((seed * 0x01000193) xor (raw.size * 0x9E3779B9.toInt()))
        val hex = StringBuilder(raw.size * 2)
        for (b in raw) {
            state = mix(state)
            val enc = (b.toInt() xor (state and 0xFF)) and 0xFF
            hex.append(Character.forDigit((enc ushr 4) and 0x0F, 16))
            hex.append(Character.forDigit(enc and 0x0F, 16))
        }
        return hex.toString()
    }

    @TaskAction
    fun generate() {
        val sections = linkedMapOf<String, MutableList<String>>()
        var current: String? = null
        iniFile.get().asFile.readLines(Charsets.UTF_8).forEach { raw ->
            val line = raw.trim()
            if (line.isEmpty() || line.startsWith("#")) return@forEach
            if (line.startsWith("[") && line.endsWith("]")) {
                current = line.substring(1, line.length - 1)
                sections.putIfAbsent(current!!, mutableListOf())
            } else if (current != null) {
                sections[current!!]!!.add(line)
            }
        }

        val javaGroups = listOf(
            Triple("SU_PATHS", "su", 0x101),
            Triple("MAGISK_PATHS", "magisk", 0x203),
            Triple("KERNELSU_PATHS", "kernelsu", 0x307),
            Triple("APATCH_PATHS", "apatch", 0x409),
            Triple("MODULE_PATHS", "modules", 0x50B),
            Triple("EMULATOR_PACKAGES", "emulator_packages", 0x60D),
            Triple("CLOUD_PACKAGES", "cloud_packages", 0x70F),
            Triple("TAMPER_TOOL_PATHS", "tamper_tool_paths", 0x913),
            Triple("ALLOWED_PROPERTIES", "properties", 0xA17),
            Triple("PARTITION_FINGERPRINT_PROPERTIES", "partition_fingerprint_properties", 0xB1D),
            Triple("CLOUD_PHONE_PROPERTIES", "cloud_phone_properties", 0xC1F),
            Triple("VIRTUAL_GPU_MARKERS", "virtual_gpu_markers", 0xD21)
        )

        val javaBuilder = StringBuilder()
        javaBuilder.appendLine("package com.wsttxm.riskenginesdk.generated;")
        javaBuilder.appendLine()
        javaBuilder.appendLine("/**")
        javaBuilder.appendLine(" * Generated from src/main/resources/lists/artifact_paths.ini via")
        javaBuilder.appendLine(" * {@code :riskengine-sdk:generateDetectionLists}. Strings are stored in")
        javaBuilder.appendLine(" * obfuscated form and decoded at class initialization.")
        javaBuilder.appendLine(" */")
        javaBuilder.appendLine("public final class DetectionLists {")
        javaBuilder.appendLine("    private DetectionLists() {}")
        javaBuilder.appendLine()
        for ((constName, section, seed) in javaGroups) {
            val items = sections[section] ?: error("Missing section [$section] in artifact_paths.ini")
            javaBuilder.appendLine("    public static final String[] $constName = ObfuscatedLists.decode(0x${seed.toString(16).uppercase()}, new String[]{")
            items.forEachIndexed { idx, value ->
                val enc = encodeOne(seed + idx, value)
                val comma = if (idx + 1 < items.size) "," else ""
                javaBuilder.appendLine("            \"$enc\"$comma")
            }
            javaBuilder.appendLine("    });")
            javaBuilder.appendLine()
        }
        javaBuilder.appendLine("}")
        javaOutput.get().asFile.writeText(javaBuilder.toString(), Charsets.UTF_8)

        val cppGroups = listOf(
            "list_su_paths" to "su",
            "list_magisk_paths" to "magisk",
            "list_kernelsu_paths" to "kernelsu",
            "list_apatch_paths" to "apatch",
            "list_module_paths" to "modules",
            "list_tamper_tool_paths" to "tamper_tool_paths",
            "list_emulator_files" to "emulator_files",
            "list_allowed_properties" to "properties",
            "list_monitored_libc_symbols" to "monitored_libc_symbols"
        )

        val cppBuilder = StringBuilder()
        cppBuilder.appendLine("#ifndef RISKENGINE_DETECTION_LISTS_H")
        cppBuilder.appendLine("#define RISKENGINE_DETECTION_LISTS_H")
        cppBuilder.appendLine()
        cppBuilder.appendLine("// Generated from src/main/resources/lists/artifact_paths.ini via")
        cppBuilder.appendLine("// :riskengine-sdk:generateDetectionLists.")
        cppBuilder.appendLine()
        cppBuilder.appendLine("#include \"../util/obf_str.h\"")
        cppBuilder.appendLine("#include <string>")
        cppBuilder.appendLine("#include <vector>")
        cppBuilder.appendLine()
        for ((fnName, section) in cppGroups) {
            val items = sections[section] ?: error("Missing section [$section] in artifact_paths.ini")
            cppBuilder.appendLine("inline std::vector<std::string> $fnName() {")
            cppBuilder.appendLine("    return {")
            items.forEachIndexed { idx, value ->
                val escaped = value.replace("\\", "\\\\").replace("\"", "\\\"")
                val comma = if (idx + 1 < items.size) "," else ""
                cppBuilder.appendLine("            OBF(\"$escaped\")$comma")
            }
            cppBuilder.appendLine("    };")
            cppBuilder.appendLine("}")
            cppBuilder.appendLine()
        }
        cppBuilder.appendLine("#endif")
        cppOutput.get().asFile.writeText(cppBuilder.toString(), Charsets.UTF_8)
    }
}

val generateDetectionLists = tasks.register<GenerateDetectionListsTask>("generateDetectionLists") {
    iniFile.set(layout.projectDirectory.file("src/main/resources/lists/artifact_paths.ini"))
    javaOutput.set(layout.projectDirectory.file("src/main/java/com/wsttxm/riskenginesdk/generated/DetectionLists.java"))
    cppOutput.set(layout.projectDirectory.file("src/main/cpp/generated/detection_lists.h"))
}

tasks.configureEach {
    if (name != "generateDetectionLists") {
        if (name == "preBuild") {
            dependsOn(generateDetectionLists)
        } else {
            mustRunAfter(generateDetectionLists)
        }
    }
}
