# RiskEngine

Mobile device risk identification SDK + risk operations management platform.

The client-side SDK is built on a Java / C++17 dual-layer architecture for device fingerprinting and environment risk detection, reporting data to the server over an AES-256-GCM encrypted channel. The server persists reported data, evaluates risk through a SpEL-based rule engine, and exposes a web console for device auditing and rule management.

---

## Table of Contents

- [Architecture](#architecture)
- [Tech Stack](#tech-stack)
- [Project Structure](#project-structure)
- [Quick Start](#quick-start)
- [SDK Documentation](#riskengine-sdk)
- [Server Documentation](#riskengine-server)
- [Deployment](#deployment)
- [Encrypted Transport](#encrypted-transport)
- [License](#license)

---

## Architecture

```
┌──────────────────┐          ┌──────────────────────────────────┐
│   Android App    │          │        RiskEngineServer          │
│                  │          │                                  │
│  ┌────────────┐  │  HTTPS   │  ┌────────────┐  ┌───────────┐  │
│  │ RiskEngine │──┼─────────►│  │ Report API │──│  Report   │  │
│  │    SDK     │  │  POST    │  │ Controller │  │  Service  │  │
│  └────────────┘  │ /api/v1  │  └────────────┘  └─────┬─────┘  │
│                  │ /report  │                         │        │
│  Collector (15)  │          │  ┌──────────┐    ┌──────▼──────┐ │
│  - Java (8)      │          │  │ AES-256  │    │ Rule Engine │ │
│  - Native (7)    │          │  │   -GCM   │    │   (SpEL)   │ │
│                  │          │  └──────────┘    └──────┬─────┘ │
│  Detector (10)   │          │                   ┌──────▼─────┐ │
│  - Root/Hook     │          │                   │   MySQL    │ │
│  - Emulator      │          │                   └────────────┘ │
│  - Debug/Repack  │          │                                  │
│                  │          │  ┌────────────────────────────┐  │
│  Anti-Tamper     │          │  │     Web Admin Console      │  │
│  - CRC Check     │          │  │  (Thymeleaf + Bootstrap 5) │  │
│  - Maps Monitor  │          │  └────────────────────────────┘  │
│  - Custom JNI    │          │                                  │
└──────────────────┘          └──────────────────────────────────┘
```

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| SDK Language | Java 11+ (Android) / C++17 (NDK) |
| SDK Build | Gradle 8.13, AGP 8.13.1, CMake 3.22.1 |
| SDK Dependencies | Gson 2.11.0, OkHttp 4.12.0, HiddenApiBypass 4.3 |
| Server | Spring Boot 4.0.5, Java 17 |
| ORM | Spring Data JPA + Hibernate |
| Database | MySQL 8.0 (prod) / H2 (dev) |
| Frontend | Thymeleaf + Bootstrap 5.3.3 |
| Auth | Spring Security (Form Login + API Key) |
| Rule Engine | Spring Expression Language (SpEL) |
| Encryption | AES-256-GCM |
| Deployment | Docker + Docker Compose |

---

## Project Structure

```
RiskEngine/
├── RiskEngineSdk/                   # Android SDK
│   ├── riskengine-sdk/              #   SDK Library (AAR)
│   │   └── src/main/
│   │       ├── java/.../riskenginesdk/
│   │       │   ├── RiskEngine.java          # Entry point (Singleton)
│   │       │   ├── RiskEngineConfig.java    # Configuration
│   │       │   ├── RiskEngineCallback.java  # Async callback
│   │       │   ├── model/                   # Data models
│   │       │   ├── core/                    # Scheduling & aggregation
│   │       │   ├── collector/               # Fingerprint collectors
│   │       │   │   ├── java_layer/          #   Java (8)
│   │       │   │   └── native_layer/        #   Native (7, JNI)
│   │       │   ├── detector/                # Risk detectors (10)
│   │       │   ├── transport/               # Network & encryption
│   │       │   └── util/
│   │       └── cpp/                         # C++ Native layer
│   │           ├── collector/
│   │           ├── detector/
│   │           ├── antitamper/
│   │           └── util/                    # syscall wrapper & ELF parser
│   └── demo/                        #   Demo App
│
└── RiskEngineServer/                # Spring Boot Server
    ├── src/main/java/.../riskengineserver/
    │   ├── config/
    │   ├── controller/
    │   │   ├── api/                         # SDK reporting endpoint
    │   │   └── web/                         # Admin pages
    │   ├── dto/
    │   ├── entity/
    │   ├── repository/
    │   ├── service/
    │   └── security/
    ├── src/main/resources/
    │   ├── application.yml                  # MySQL config
    │   ├── application-dev.yml              # H2 config
    │   ├── templates/
    │   └── static/
    ├── sql/init.sql
    ├── Dockerfile
    └── docker-compose.yml
```

---

## Quick Start

A `build.sh` script is provided at the project root (macOS ARM64):

```bash
./build.sh <command>
```

| Command | Description |
|---------|-------------|
| `server` | Build Server JAR |
| `server-run` | Build and run Server in H2 mode (no MySQL required) |
| `sdk` | Build SDK AAR |
| `demo` | Build Demo APK (debug); auto-installs if a device is connected |
| `docker` | Start Server + MySQL via Docker Compose |
| `docker-stop` | Stop Docker Compose services |
| `clean` | Clean all build artifacts |
| `all` | Build Server + SDK |

### Deploy Server

**Docker Compose (recommended)**

> Prerequisites: Docker 20.10+, Docker Compose v2+

```bash
./build.sh docker

# View logs
cd RiskEngineServer && docker compose logs -f riskengine-server
```

**Local (H2, no MySQL)**

> Prerequisites: JDK 17+

```bash
./build.sh server-run
```

Open `http://localhost:8080` and log in with `admin` / `admin123`.

Navigate to *App Management* to create an application and obtain the **App Key** for SDK integration.

### Build SDK / Demo

> Prerequisites: JDK 17+, Android SDK (API 36), NDK, CMake 3.22+

```bash
./build.sh sdk     # Output: AAR
./build.sh demo    # Output: Debug APK
```

### Integrate the SDK

**Add dependency**

```kotlin
// settings.gradle.kts
include(":riskengine-sdk")

// app/build.gradle.kts
dependencies {
    implementation(project(":riskengine-sdk"))
}
```

**Initialize**

```java
RiskEngineConfig config = new RiskEngineConfig.Builder()
        .serverUrl("http://your-server:8080")
        .appKey("your-app-key")
        .debugLog(BuildConfig.DEBUG)
        .build();

RiskEngine.init(context, config);
```

**Collect and report**

```java
RiskEngine.collect(new RiskEngineCallback() {
    @Override
    public void onSuccess(RiskReport report) {
        Log.d("RiskEngine", "Risk: " + report.getOverallRiskLevel());
    }

    @Override
    public void onError(Throwable error) {
        Log.e("RiskEngine", "Error", error);
    }
});
```

Reported data can be viewed in the web admin console.

---

## RiskEngine SDK

### Capabilities

| Capability | Description |
|------------|-------------|
| Device Fingerprinting | 15 collectors (8 Java + 7 Native) covering Android ID / Build / DRM / MAC / CPU etc. |
| Cross-layer Verification | Same data point collected independently at Java and Native layers; inconsistency is flagged as a tampering signal |
| Environment Risk Detection | 10 detectors covering Root / Hook / Emulator / Sandbox / Debug / Repackage / Cloud Phone etc. |
| Native Syscall | Bypasses libc via raw kernel calls (`__NR_openat` / `__NR_read` etc.) to counter LD_PRELOAD / PLT hooks |
| Anti-Tamper | ELF .text/.plt CRC verification, /proc/self/maps redirect detection, custom JNI registration |
| Encrypted Reporting | AES-256-GCM + OkHttp HTTPS, heartbeat & server-side config push |
| Risk Levels | Five-tier model: SAFE(0) / LOW(1) / MEDIUM(2) / HIGH(3) / DEADLY(4) |

### SDK Architecture

```
┌─────────────────────────────────────────────────────────┐
│                      App Layer                           │
│                  RiskEngine.init() / collect()            │
├─────────────────────────────────────────────────────────┤
│                     Public API                           │
│          RiskEngine / RiskEngineConfig / Callback         │
├──────────────────┬──────────────────────────────────────┤
│   Java Collector  │         Java Detector                │
│  AndroidId (x4)   │  Root / Hook / Emulator / Sandbox    │
│  BuildProps       │  Debug / Repackage / CloudPhone      │
│  Screen / WiFi    │  CustomRom / ProcessScan / Mount     │
│  Bluetooth / ...  │                                      │
├──────────────────┼──────────────────────────────────────┤
│              Core (TaskScheduler + DataAggregator)        │
├──────────────────┴──────────────────────────────────────┤
│                    JNI Bridge (22 methods)                │
├─────────────────────────────────────────────────────────┤
│                    Native C++ Layer                       │
│  ┌─────────────┐ ┌──────────────┐ ┌──────────────────┐  │
│  │ syscall_wrap │ │ Collectors   │ │   Detectors      │  │
│  │ (raw syscall)│ │ DRM/Boot/CPU │ │  Root/Hook/Debug │  │
│  │             │ │ MAC/Disk/... │ │  Emulator/Seccomp│  │
│  └─────────────┘ └──────────────┘ └──────────────────┘  │
│  ┌──────────────────────────────────────────────────┐   │
│  │         Anti-Tamper (CRC / Maps / Custom JNI)     │   │
│  └──────────────────────────────────────────────────┘   │
├─────────────────────────────────────────────────────────┤
│                   Transport Layer                         │
│       AES-256-GCM → OkHttp HTTPS → Server                │
└─────────────────────────────────────────────────────────┘
```

### Requirements

| Item | Requirement |
|------|-------------|
| minSdk | 30 (Android 11) |
| compileSdk | 36 |
| NDK | CMake 3.22.1+ |
| ABI | arm64-v8a, armeabi-v7a |
| Java | 11+ |
| C++ | C++17 |
| Gradle | 8.13 (AGP 8.13.1) |

### Configuration

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `serverUrl` | String | null | Server URL; reporting is disabled if unset |
| `appKey` | String | null | Application key |
| `encryptionKey` | byte[] | null | AES-256 key (32 bytes); enables encrypted transport |
| `expectedSignature` | String | null | Expected APK SHA-256 digest for repackage detection |
| `enableRoot` | boolean | true | Root detection |
| `enableHookDetection` | boolean | true | Hook framework detection |
| `enableEmulatorDetection` | boolean | true | Emulator detection |
| `enableSandboxDetection` | boolean | true | Sandbox detection |
| `enableDebugDetection` | boolean | true | Debug detection |
| `enableRepackageDetection` | boolean | true | Repackage detection |
| `enableCloudPhoneDetection` | boolean | true | Cloud phone detection |
| `enableCustomRomDetection` | boolean | true | Custom ROM detection |
| `debugLog` | boolean | false | Debug logging |
| `collectTimeout` | long | 10000 | Collection timeout (ms) |

### API Reference

**RiskEngine**

| Method | Description |
|--------|-------------|
| `init(Context, RiskEngineConfig)` | Initialize; must be called before any other method |
| `collect(RiskEngineCallback)` | Async fingerprint collection + detection |
| `collectSync()` | Synchronous collection (blocking) |
| `startHeartbeat(long intervalMs)` | Start periodic heartbeat reporting |
| `shutdown()` | Release resources and stop heartbeat |
| `getReportJson()` | Get the latest report as JSON |
| `isInitialized()` | Query initialization state |

**RiskReport**

| Method | Description |
|--------|-------------|
| `getOverallRiskLevel()` | Aggregate risk level (max across all detectors) |
| `getFingerprint()` | Device fingerprint |
| `getDetections()` | List of detection results |
| `getDetectionsByLevel(RiskLevel)` | Filter by minimum level |
| `getTimestampMs()` | Report timestamp |
| `getSdkVersion()` | SDK version |

**RiskLevel**

| Level | Value | Meaning |
|-------|-------|---------|
| SAFE | 0 | No risk |
| LOW | 1 | Low risk (e.g., custom ROM) |
| MEDIUM | 2 | Medium risk (e.g., emulator traits) |
| HIGH | 3 | High risk (e.g., Root / sandbox / debugging) |
| DEADLY | 4 | Critical risk (e.g., hook framework / repackage) |

### Fingerprint Collectors

#### Java Layer (8)

| Collector | Data | Method |
|-----------|------|--------|
| AndroidIdCollector | ANDROID_ID | 4 methods: Settings API / NameValueCache reflection (HiddenApiBypass) / ContentResolver.call / content query shell |
| BuildPropsCollector | Build properties | 19 fields: BOARD / BRAND / DEVICE / DISPLAY / FINGERPRINT / HARDWARE / HOST / ID / MANUFACTURER / MODEL / PRODUCT / TAGS / TYPE / USER / SOC_MANUFACTURER / SOC_MODEL / BOOTLOADER / RADIO / SERIAL |
| ScreenInfoCollector | Screen metrics | DisplayMetrics: width / height / density / densityDpi / xdpi / ydpi |
| ApkSignatureCollector | APK signature | PackageManager SHA-256 + Parcelable CREATOR ClassLoader verification |
| BluetoothMacCollector | Bluetooth MAC | BluetoothAdapter reflection for real address |
| WifiInfoCollector | WiFi info | WifiManager: MAC / SSID / BSSID / IP / Link Speed / RSSI |
| TelephonyCollector | Telephony info | TelephonyManager: IMEI / Subscriber ID / Network & SIM Operator (graceful degradation without permissions) |
| SettingsCollector | System settings | Settings.Secure / Global hidden fields |

#### Native Layer (7)

| Collector | Data | Method |
|-----------|------|--------|
| drm_collector | DRM Widevine device ID | JNI call to MediaDrm |
| boot_id_collector | Boot ID | syscall read `/proc/sys/kernel/random/boot_id` |
| system_property_collector | System properties | `__system_property_get` |
| cpu_info_collector | CPU info | syscall parse `/proc/cpuinfo` |
| disk_size_collector | Disk capacity | `__NR_statfs` |
| mac_netlink_collector | MAC address | Netlink RTM_NEWLINK (bypasses MAC randomization) |
| kernel_info_collector | Kernel version | `uname()` |

#### Cross-layer Verification

`DataAggregator` compares Java and Native results for the same data point. Discrepancies are flagged as INCONSISTENT — this flag itself serves as a tampering indicator.

### Risk Detectors

| Detector | Level | Detection Points |
|----------|-------|-----------------|
| RootDetector | HIGH | su binary (10 paths) / Magisk (5 paths) / SELinux status / test-keys / Native syscall cross-verification |
| HookFrameworkDetector | DEADLY | Xposed (reflection + call stack) / Frida (maps scan + port 27042 + thread name) / Native CRC |
| EmulatorDetector | HIGH/MEDIUM | Build property keywords / hardware traits / emulator files (18 paths) / thermal zone / Seccomp BPF x86 detection / sensor count |
| SandboxDetector | HIGH | /proc process count analysis / fd scanning / multi-user UID |
| DebugDetector | HIGH | TracerPid / debuggable flag / IDA Pro port 23946 / ptrace self-check |
| RepackageDetector | DEADLY | Java vs Native signature cross-comparison / expected signature check / ClassLoader verification |
| CloudPhoneDetector | HIGH/MEDIUM | Abnormal battery voltage / camera count < 2 / sensor count < 3 |
| CustomRomDetector | LOW | 10 ROM property signatures (MIUI / ColorOS / Flyme / EMUI / OneUI etc.) / LineageOS |
| ProcessScanDetector | HIGH | ps scan for suspicious processes (frida / xposed / magisk / gdb / ida) / service list |
| MountAnalysisDetector | MEDIUM | /proc/mounts analysis for Magisk overlay / Docker / module mounts |

### Anti-Tamper

| Module | Mechanism |
|--------|-----------|
| memory_crc_checker | Saves CRC32 of `libriskengine.so` .text/.plt sections at init; compares at runtime to detect code hooks/patches |
| maps_monitor | Opens `/proc/self/maps` via syscall; verifies fd readlink path is not redirected |
| custom_jni_register | Bypasses standard `RegisterNatives` to counter JNI hooks |
| elf_parser | Parses ELF Section Headers to locate .text/.plt and compute CRC32 |

**Syscall wrapper**: All file operations go through `syscall()` directly, bypassing the libc function table:

| Function | Syscall | Purpose |
|----------|---------|---------|
| my_openat | `__NR_openat` | Open file |
| my_read | `__NR_read` | Read |
| my_write | `__NR_write` | Write |
| my_close | `__NR_close` | Close fd |
| my_readlinkat | `__NR_readlinkat` | Read symlink |
| my_fstat | `__NR_fstat` | File status |
| my_access | `__NR_faccessat` | Existence check |
| my_getdents64 | `__NR_getdents64` | Read directory entries |

**Seccomp BPF architecture detection**: Installs a BPF filter that returns `SECCOMP_RET_ERRNO` for `getpid` only on x86/x86_64. If `getpid()` returns an error, the process is running under an x86 translation layer — a strong emulator indicator, capable of detecting x86 emulators that use ARM translation.

**Netlink MAC collection**: Uses `NETLINK_ROUTE` + `RTM_GETLINK` to retrieve NIC MAC addresses directly from the kernel, bypassing Android 10+ MAC randomization and the `02:00:00:00:00:00` placeholder returned by the Java API.

### Transport

| Component | Responsibility |
|-----------|---------------|
| ReportSerializer | Gson serialization: RiskReport → JSON |
| DataEncryptor | AES-256-GCM (12B IV + 128-bit tag), Base64 encoded |
| TransportClient | OkHttp POST to `{serverUrl}/api/v1/report` with `X-App-Key` header |
| HeartbeatManager | ScheduledExecutorService for periodic collection and reporting |
| ServerConfigReceiver | Parses server response: collection interval / detector toggles / kill switch |

**Report JSON example**

```json
{
  "sdkVersion": "1.0.0",
  "timestampMs": 1712899200000,
  "overallRiskLevel": "MEDIUM",
  "fingerprint": {
    "results": {
      "android_id": {
        "fieldName": "android_id",
        "values": {
          "settings_api": "a1b2c3d4e5f6",
          "content_resolver": "a1b2c3d4e5f6"
        },
        "consistent": true,
        "canonicalValue": "a1b2c3d4e5f6"
      }
    },
    "inconsistentFields": []
  },
  "detections": [
    {
      "detectorName": "EmulatorDetector",
      "riskLevel": "MEDIUM",
      "evidence": "thermal_zones=0"
    }
  ]
}
```

### Build

Dependency versions are managed via [Gradle Version Catalog](https://docs.gradle.org/current/userguide/platforms.html) (`gradle/libs.versions.toml`).

```bash
cd RiskEngineSdk

./gradlew :riskengine-sdk:assembleDebug     # Debug AAR
./gradlew :riskengine-sdk:assembleRelease   # Release AAR (R8)
./gradlew :demo:installDebug                # Demo App

./gradlew :riskengine-sdk:testDebugUnitTest           # Unit tests
./gradlew :riskengine-sdk:connectedDebugAndroidTest   # Instrumented tests
```

AAR output: `riskengine-sdk/build/outputs/aar/`

### ProGuard

The SDK ships with `consumer-rules.pro`; no additional configuration is needed by the integrating app. The following public APIs are kept through obfuscation:

- `com.wsttxm.riskenginesdk.RiskEngine`
- `com.wsttxm.riskenginesdk.RiskEngineConfig`
- `com.wsttxm.riskenginesdk.RiskEngineCallback`
- `com.wsttxm.riskenginesdk.model.RiskReport`
- `com.wsttxm.riskenginesdk.model.RiskLevel`

All JNI native methods are retained automatically. Release builds use `-repackageclasses 'a'` for aggressive obfuscation.

---

## RiskEngine Server

### Features

- Receives SDK-reported data (plaintext or AES-256-GCM encrypted)
- Generates unique device IDs (SHA-256) from key fingerprint fields; tracks device reporting history
- SpEL rule engine with hot-reload — add, modify, or disable rules without restarting the server
- Web admin console: Dashboard / Device Management / Reports / Rule Management / App Management
- Multi-app isolation with independent App Key and encryption key per application

### Database Schema

```
┌─────────┐     ┌──────────────┐     ┌─────────┐
│   App   │──┐  │ DeviceReport │  ┌──│ Device  │
│         │  └─►│              │◄─┘  │         │
│ appKey  │     │ fingerprintJson   │ deviceId│
│ appName │     │ detectionsJson    │ riskLevel
│ encKey  │     │ riskLevel    │     │ riskMarked
└─────────┘     └──────┬───────┘     └────┬────┘
                       │                  │
                       ▼                  ▼
               ┌───────────────┐  ┌──────────────┐
               │ RuleHitRecord │  │RuleDefinition│
               │               │  │              │
               │ detail        │  │ ruleExpression
               │ hitAt         │  │ riskLevel    │
               └───────────────┘  │ enabled      │
                                  └──────────────┘
```

| Table | Description | Key Fields |
|-------|-------------|-----------|
| app | Registered applications | appKey (unique), appName, encryptionKey, enabled |
| device | Devices | deviceId (SHA-256, unique), lastRiskLevel, riskMarked, reportCount |
| device_report | Reports | fingerprintJson, detectionsJson, overallRiskLevel, receivedAt |
| rule_definition | Rules | ruleName, ruleExpression (SpEL), riskLevel, enabled |
| rule_hit_record | Rule hits | rule, device, report, hitAt, detail |

### API

#### POST /api/v1/report

**Request Headers**

| Header | Required | Description |
|--------|----------|-------------|
| X-App-Key | Yes | Application key |
| X-Encrypted | No | `true` / `false`, defaults to `false` |
| Content-Type | Yes | `application/json` |

**Example Request**

```bash
curl -X POST http://localhost:8080/api/v1/report \
  -H "Content-Type: application/json" \
  -H "X-App-Key: your-app-key" \
  -H "X-Encrypted: false" \
  -d '{
    "sdk_version": "1.0.0",
    "timestamp_ms": 1712900000000,
    "overall_risk_level": "HIGH",
    "fingerprint": {
      "results": {
        "android_id": {
          "field_name": "android_id",
          "values": {"android_id": "abc123"},
          "consistent": true,
          "canonical_value": "abc123"
        }
      },
      "inconsistent_fields": []
    },
    "detections": [
      {
        "detector_name": "RootDetector",
        "risk_level": "HIGH",
        "evidence": ["su binary found at /system/xbin/su"]
      }
    ]
  }'
```

**Response**

```json
{
  "status": "ok",
  "collect_interval": 1800000,
  "enabled_detectors": [],
  "kill_switch": false
}
```

**Error Codes**

| HTTP Status | Reason |
|-------------|--------|
| 400 | Missing X-App-Key / malformed JSON / decryption failure |
| 401 | Invalid App Key |
| 403 | Application disabled |

### Rule Engine

SpEL-based; rules can be added, modified, or toggled at runtime without restarting.

**Context Variables**

| Variable | Type | Description |
|----------|------|-------------|
| overallRiskLevel | String | Aggregate risk level |
| detections | List | Detection results |
| fingerprint | Map | Fingerprint data |
| inconsistentFields | List | Inconsistent fields |
| reportCount | int | Device historical report count |
| riskMarked | boolean | Whether the device is manually flagged |

**Rule Examples**

```
# DEADLY devices
overallRiskLevel == 'DEADLY'

# Rooted
detections.?[detectorName == 'RootDetector' and riskLevel == 'HIGH'].size() > 0

# Hook framework
detections.?[detectorName == 'HookFrameworkDetector' and riskLevel != 'SAFE'].size() > 0

# Fingerprint inconsistency > 2 fields
inconsistentFields.size() > 2

# High-frequency reporting
reportCount > 100

# Emulator
detections.?[detectorName == 'EmulatorDetector' and riskLevel == 'HIGH'].size() > 0
```

### Web Admin Console

Built with Thymeleaf + Bootstrap 5.

| Page | Path | Function |
|------|------|----------|
| Dashboard | /dashboard | Total devices / high-risk count / today's reports / rule hit stats |
| Devices | /devices | Device list (paginated, risk-level filter) / device detail / manual flagging |
| Reports | /reports | Report list / fingerprint & detection JSON viewer |
| Rules | /rules | Rule CRUD / enable-disable toggle |
| Apps | /apps | App creation / disable / key & secret management |
| Login | /login | Admin authentication |

### Security

- API layer (`/api/**`): stateless, application identity verified via `X-App-Key` header
- Web layer: Spring Security form-based login

---

## Deployment

### Docker (recommended)

> Prerequisites: Docker 20.10+, Docker Compose v2+

```bash
cd RiskEngineServer
docker-compose up -d
docker-compose logs -f riskengine-server
```

- Web console: `http://<host>:8080`
- Credentials: `admin` / `admin123`

Custom configuration (`docker-compose.yml`):

```yaml
environment:
  MYSQL_PASSWORD: your_mysql_password
  ADMIN_USERNAME: your_admin
  ADMIN_PASSWORD: your_password
```

Stop:

```bash
docker-compose down        # Preserve data
docker-compose down -v     # Remove volumes
```

### Local Development

> Prerequisites: JDK 17+

**H2 (no MySQL required)**

```bash
cd RiskEngineServer
./gradlew bootRun --args='--spring.profiles.active=dev'
```

- App: `http://localhost:8080`
- H2 Console: `http://localhost:8080/h2-console` (JDBC URL: `jdbc:h2:file:./data/risk_engine;AUTO_SERVER=TRUE`, user: `sa`, password: empty)

**MySQL**

```bash
mysql -u root -p -e "CREATE DATABASE risk_engine CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
mysql -u root -p -e "CREATE USER 'risk_engine'@'localhost' IDENTIFIED BY 'risk_engine_pass';"
mysql -u root -p -e "GRANT ALL PRIVILEGES ON risk_engine.* TO 'risk_engine'@'localhost';"

cd RiskEngineServer
./gradlew bootRun
```

**Build & Test**

```bash
cd RiskEngineServer
./gradlew bootJar
java -jar build/libs/RiskEngineServer-0.0.1-SNAPSHOT.jar

./gradlew test
```

**Environment Variables**

| Variable | Default | Description |
|----------|---------|-------------|
| MYSQL_PASSWORD | risk_engine_pass | MySQL password |
| ADMIN_USERNAME | admin | Web admin username |
| ADMIN_PASSWORD | admin123 | Web admin password |

---

## Encrypted Transport

AES-256-GCM encrypted channel between SDK and Server:

```
SDK                                       Server
  │                                          │
  │  1. Collect + detect                     │
  │  2. Serialize to JSON                    │
  │  3. AES-256-GCM encrypt                 │
  │     - 12 byte random IV                 │
  │     - ciphertext + 16 byte auth tag     │
  │     - concat: IV + ciphertext + tag     │
  │     - Base64 encode                     │
  │                                          │
  │  POST /api/v1/report                     │
  │  X-App-Key: xxx                          │
  │  X-Encrypted: true                       │
  │  Body: Base64(IV + ciphertext + tag)     │
  │ ────────────────────────────────────────► │
  │                                          │  4. Base64 decode
  │                                          │  5. Extract IV (first 12 bytes)
  │                                          │  6. AES-256-GCM decrypt
  │                                          │  7. Parse JSON
  │                                          │  8. Process report
```

Key management:

- Each application has an independent AES-256 key (32 bytes), generated when the application is created on the server
- SDK-side: configured via `RiskEngineConfig.Builder.encryptionKey(byte[])`
- Without an encryption key, data is reported in plaintext; the server accepts both modes

SDK-side setup:

```java
RiskEngineConfig config = new RiskEngineConfig.Builder()
        .serverUrl("https://your-server.com")
        .appKey("your-app-key")
        .encryptionKey(Base64.decode(encKeyBase64, Base64.NO_WRAP))
        .build();
```

---

## License

[MIT](LICENSE)
