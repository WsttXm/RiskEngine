# RiskEngine

移动端设备风控 SDK + 风险运营管理后台。

客户端基于 Java / C++17 双层架构实现设备指纹采集与环境风险检测，通过 AES-256-GCM 加密通道上报至服务端；服务端持久化上报数据，通过 SpEL 规则引擎执行自动化风险判定，并提供 Web 管理界面进行设备审计与规则运营。

---

## 目录

- [架构](#架构)
- [技术栈](#技术栈)
- [目录结构](#目录结构)
- [快速开始](#快速开始)
- [SDK 文档](#riskengine-sdk)
- [Server 文档](#riskengine-server)
- [部署](#部署)
- [加密传输](#加密传输)
- [License](#license)

---

## 架构

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

## 技术栈

| 组件 | 技术 |
|------|------|
| SDK 语言 | Java 11+ (Android) / C++17 (NDK) |
| SDK 构建 | Gradle 8.13, AGP 8.13.1, CMake 3.22.1 |
| SDK 依赖 | Gson 2.11.0, OkHttp 4.12.0, HiddenApiBypass 4.3 |
| 服务端 | Spring Boot 4.0.5, Java 17 |
| ORM | Spring Data JPA + Hibernate |
| 数据库 | MySQL 8.0 (prod) / H2 (dev) |
| 前端 | Thymeleaf + Bootstrap 5.3.3 |
| 认证 | Spring Security (Form Login + API Key) |
| 规则引擎 | Spring Expression Language (SpEL) |
| 加密 | AES-256-GCM |
| 部署 | Docker + Docker Compose |

---

## 目录结构

```
RiskEngine/
├── RiskEngineSdk/                   # Android SDK
│   ├── riskengine-sdk/              #   SDK Library (AAR)
│   │   └── src/main/
│   │       ├── java/.../riskenginesdk/
│   │       │   ├── RiskEngine.java          # 入口 (Singleton)
│   │       │   ├── RiskEngineConfig.java    # 配置
│   │       │   ├── RiskEngineCallback.java  # 异步回调
│   │       │   ├── model/                   # 数据模型
│   │       │   ├── core/                    # 调度 & 聚合
│   │       │   ├── collector/               # 指纹采集器
│   │       │   │   ├── java_layer/          #   Java (8)
│   │       │   │   └── native_layer/        #   Native (7, JNI)
│   │       │   ├── detector/                # 风险检测器 (10)
│   │       │   ├── transport/               # 网络 & 加密
│   │       │   └── util/
│   │       └── cpp/                         # C++ Native
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
    │   │   ├── api/                         # SDK 上报接口
    │   │   └── web/                         # 管理页面
    │   ├── dto/
    │   ├── entity/
    │   ├── repository/
    │   ├── service/
    │   └── security/
    ├── src/main/resources/
    │   ├── application.yml                  # MySQL 配置
    │   ├── application-dev.yml              # H2 配置
    │   ├── templates/
    │   └── static/
    ├── sql/init.sql
    ├── Dockerfile
    └── docker-compose.yml
```

---

## 快速开始

项目根目录提供 `build.sh` 构建脚本（macOS ARM64）：

```bash
./build.sh <command>
```

| 命令 | 说明 |
|------|------|
| `server` | 构建 Server JAR |
| `server-run` | 构建并以 H2 模式启动 Server，不依赖 MySQL |
| `sdk` | 构建 SDK AAR |
| `demo` | 构建 Demo APK (debug)，连接设备时自动安装 |
| `docker` | Docker Compose 拉起 Server + MySQL |
| `docker-stop` | 停止 Docker Compose |
| `clean` | 清理全部构建产物 |
| `all` | 构建 Server + SDK |

### 部署服务端

**Docker Compose（推荐）**

> 前置：Docker 20.10+、Docker Compose v2+

```bash
./build.sh docker

# 查看日志
cd RiskEngineServer && docker compose logs -f riskengine-server
```

**本地运行（H2）**

> 前置：JDK 17+

```bash
./build.sh server-run
```

启动后访问 `http://localhost:8080`，默认账号 `admin` / `admin123`。

在「应用管理」中创建应用，获取 App Key 供 SDK 接入。

### 构建 SDK / Demo

> 前置：JDK 17+、Android SDK (API 36)、NDK、CMake 3.22+

```bash
./build.sh sdk     # 输出 AAR
./build.sh demo    # 输出 Debug APK
```

### SDK 接入

**添加依赖**

```kotlin
// settings.gradle.kts
include(":riskengine-sdk")

// app/build.gradle.kts
dependencies {
    implementation(project(":riskengine-sdk"))
}
```

**初始化**

```java
RiskEngineConfig config = new RiskEngineConfig.Builder()
        .serverUrl("http://your-server:8080")
        .appKey("your-app-key")
        .debugLog(BuildConfig.DEBUG)
        .build();

RiskEngine.init(context, config);
```

**采集上报**

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

上报成功后可在管理后台查看对应设备数据与风险检测结果。

---

## RiskEngine SDK

### 能力矩阵

| 能力 | 说明 |
|------|------|
| 设备指纹 | 15 采集器 (8 Java + 7 Native)，覆盖 Android ID / Build / DRM / MAC / CPU 等 |
| 多源交叉校验 | 同一数据点 Java 层与 Native 层独立采集，不一致时标记为篡改信号 |
| 环境风险检测 | 10 检测器，覆盖 Root / Hook / Emulator / Sandbox / Debug / Repackage / CloudPhone 等 |
| Native syscall | 绕过 libc 直接执行内核调用 (`__NR_openat` / `__NR_read` 等)，对抗 LD_PRELOAD / PLT hook |
| 反篡改 | ELF .text/.plt CRC 校验、/proc/self/maps 重定向检测、自定义 JNI 注册 |
| 加密上报 | AES-256-GCM + OkHttp HTTPS，支持心跳与服务端配置下发 |
| 风险等级 | 五级模型：SAFE(0) / LOW(1) / MEDIUM(2) / HIGH(3) / DEADLY(4) |

### SDK 架构

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

### 环境要求

| 项目 | 要求 |
|------|------|
| minSdk | 30 (Android 11) |
| compileSdk | 36 |
| NDK | CMake 3.22.1+ |
| ABI | arm64-v8a, armeabi-v7a |
| Java | 11+ |
| C++ | C++17 |
| Gradle | 8.13 (AGP 8.13.1) |

### 配置项

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `serverUrl` | String | null | 服务端地址，不配置则不上报 |
| `appKey` | String | null | 应用密钥 |
| `encryptionKey` | byte[] | null | AES-256 密钥 (32 bytes)，配置后启用加密传输 |
| `expectedSignature` | String | null | APK SHA-256 签名摘要，用于重打包检测 |
| `enableRoot` | boolean | true | Root 检测 |
| `enableHookDetection` | boolean | true | Hook 框架检测 |
| `enableEmulatorDetection` | boolean | true | 模拟器检测 |
| `enableSandboxDetection` | boolean | true | 沙箱检测 |
| `enableDebugDetection` | boolean | true | 调试检测 |
| `enableRepackageDetection` | boolean | true | 重打包检测 |
| `enableCloudPhoneDetection` | boolean | true | 云手机检测 |
| `enableCustomRomDetection` | boolean | true | 自定义 ROM 检测 |
| `debugLog` | boolean | false | 调试日志 |
| `collectTimeout` | long | 10000 | 采集超时 (ms) |

### API

**RiskEngine**

| 方法 | 说明 |
|------|------|
| `init(Context, RiskEngineConfig)` | 初始化，须在其余方法前调用 |
| `collect(RiskEngineCallback)` | 异步采集指纹 + 检测 |
| `collectSync()` | 同步采集（阻塞） |
| `startHeartbeat(long intervalMs)` | 启动定时心跳上报 |
| `shutdown()` | 释放资源，停止心跳 |
| `getReportJson()` | 取最近一次报告的 JSON |
| `isInitialized()` | 初始化状态查询 |

**RiskReport**

| 方法 | 说明 |
|------|------|
| `getOverallRiskLevel()` | 综合风险等级（各检测项最高值） |
| `getFingerprint()` | 设备指纹 |
| `getDetections()` | 检测结果列表 |
| `getDetectionsByLevel(RiskLevel)` | 按等级过滤 |
| `getTimestampMs()` | 报告时间戳 |
| `getSdkVersion()` | SDK 版本 |

**RiskLevel**

| 等级 | 值 | 含义 |
|------|----|------|
| SAFE | 0 | 无风险 |
| LOW | 1 | 低风险 (如定制 ROM) |
| MEDIUM | 2 | 中风险 (如模拟器特征) |
| HIGH | 3 | 高风险 (如 Root / 沙箱 / 调试) |
| DEADLY | 4 | 极高风险 (如 Hook 框架 / 重打包) |

### 设备指纹采集器

#### Java 层 (8)

| 采集器 | 数据 | 方法 |
|--------|------|------|
| AndroidIdCollector | ANDROID_ID | Settings API / NameValueCache 反射 (HiddenApiBypass) / ContentResolver.call / content query shell，共 4 种 |
| BuildPropsCollector | Build 属性 | 19 字段：BOARD / BRAND / DEVICE / DISPLAY / FINGERPRINT / HARDWARE / HOST / ID / MANUFACTURER / MODEL / PRODUCT / TAGS / TYPE / USER / SOC_MANUFACTURER / SOC_MODEL / BOOTLOADER / RADIO / SERIAL |
| ScreenInfoCollector | 屏幕参数 | DisplayMetrics：宽 / 高 / density / densityDpi / xdpi / ydpi |
| ApkSignatureCollector | APK 签名 | PackageManager SHA-256 + Parcelable CREATOR ClassLoader 校验 |
| BluetoothMacCollector | 蓝牙 MAC | BluetoothAdapter 反射取真实地址 |
| WifiInfoCollector | WiFi 信息 | WifiManager：MAC / SSID / BSSID / IP / Link Speed / RSSI |
| TelephonyCollector | 电话信息 | TelephonyManager：IMEI / Subscriber ID / Network & SIM Operator（无权限安全降级） |
| SettingsCollector | 系统设置 | Settings.Secure / Global 隐藏字段 |

#### Native 层 (7)

| 采集器 | 数据 | 方法 |
|--------|------|------|
| drm_collector | DRM Widevine 设备 ID | JNI 调用 MediaDrm |
| boot_id_collector | Boot ID | syscall 读 `/proc/sys/kernel/random/boot_id` |
| system_property_collector | 系统属性 | `__system_property_get` |
| cpu_info_collector | CPU 信息 | syscall 解析 `/proc/cpuinfo` |
| disk_size_collector | 磁盘容量 | `__NR_statfs` |
| mac_netlink_collector | MAC 地址 | Netlink RTM_NEWLINK（绕过 MAC 随机化） |
| kernel_info_collector | 内核版本 | `uname()` |

#### 多源校验

`DataAggregator` 对同一数据点的 Java / Native 采集结果做一致性比对，不一致时标记为 INCONSISTENT——该标记本身即为环境篡改信号。

### 环境风险检测器

| 检测器 | 等级 | 检测点 |
|--------|------|--------|
| RootDetector | HIGH | su 二进制 (10 路径) / Magisk (5 路径) / SELinux 状态 / test-keys / Native syscall 交叉验证 |
| HookFrameworkDetector | DEADLY | Xposed (反射 + 调用栈) / Frida (maps 扫描 + 27042 端口 + 线程名) / Native CRC |
| EmulatorDetector | HIGH/MEDIUM | Build 属性关键词 / 硬件特征 / 模拟器文件 (18 路径) / thermal zone / Seccomp BPF x86 架构检测 / 传感器数量 |
| SandboxDetector | HIGH | /proc 进程数分析 / fd 扫描 / 多用户 UID |
| DebugDetector | HIGH | TracerPid / debuggable flag / IDA Pro 端口 23946 / ptrace 自检 |
| RepackageDetector | DEADLY | Java vs Native 签名交叉比对 / 预期签名校验 / ClassLoader 验证 |
| CloudPhoneDetector | HIGH/MEDIUM | 电池电压异常 / Camera < 2 / 传感器 < 3 |
| CustomRomDetector | LOW | 10 种 ROM 特征属性 (MIUI / ColorOS / Flyme / EMUI / OneUI 等) / LineageOS |
| ProcessScanDetector | HIGH | ps 扫描可疑进程 (frida / xposed / magisk / gdb / ida) / service list |
| MountAnalysisDetector | MEDIUM | /proc/mounts Magisk overlay / Docker / module 挂载分析 |

### 反篡改

| 模块 | 机制 |
|------|------|
| memory_crc_checker | 初始化时保存 `libriskengine.so` .text / .plt 段 CRC32，运行时对比检测 code hook / patch |
| maps_monitor | syscall 打开 `/proc/self/maps`，验证 fd readlink 路径是否被重定向 |
| custom_jni_register | 绕过标准 `RegisterNatives`，对抗 JNI hook |
| elf_parser | 解析 ELF Section Header 定位 .text / .plt，计算 CRC32 |

**syscall wrapper**：全部通过 `syscall()` 直接发起内核调用，不经过 libc 函数表：

| 函数 | syscall | 用途 |
|------|---------|------|
| my_openat | `__NR_openat` | 打开文件 |
| my_read | `__NR_read` | 读取 |
| my_write | `__NR_write` | 写入 |
| my_close | `__NR_close` | 关闭 fd |
| my_readlinkat | `__NR_readlinkat` | 读符号链接 |
| my_fstat | `__NR_fstat` | 文件状态 |
| my_access | `__NR_faccessat` | 存在性检查 |
| my_getdents64 | `__NR_getdents64` | 读目录项 |

**Seccomp BPF 架构检测**：安装 BPF filter，对 `getpid` syscall 仅在 x86/x86_64 架构下返回 `SECCOMP_RET_ERRNO`。若 `getpid()` 返回错误，说明当前运行于 x86 翻译层（模拟器特征），可识别使用 ARM 翻译的 x86 模拟器。

**Netlink MAC 采集**：通过 `NETLINK_ROUTE` + `RTM_GETLINK` 从内核获取网卡 MAC 地址，绕过 Android 10+ MAC 随机化及 Java API 返回 `02:00:00:00:00:00` 的限制。

### 数据传输

| 组件 | 职责 |
|------|------|
| ReportSerializer | Gson 序列化 RiskReport → JSON |
| DataEncryptor | AES-256-GCM (12B IV + 128-bit tag)，Base64 编码 |
| TransportClient | OkHttp POST `{serverUrl}/api/v1/report`，携带 `X-App-Key` |
| HeartbeatManager | ScheduledExecutorService 定时采集上报 |
| ServerConfigReceiver | 解析服务端响应：采集间隔 / 检测器开关 / kill switch |

**上报 JSON 示例**

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

### 构建

依赖版本通过 [Gradle Version Catalog](https://docs.gradle.org/current/userguide/platforms.html)（`gradle/libs.versions.toml`）管理。

```bash
cd RiskEngineSdk

./gradlew :riskengine-sdk:assembleDebug     # Debug AAR
./gradlew :riskengine-sdk:assembleRelease   # Release AAR (R8)
./gradlew :demo:installDebug                # Demo App

./gradlew :riskengine-sdk:testDebugUnitTest           # 单元测试
./gradlew :riskengine-sdk:connectedDebugAndroidTest   # 设备测试
```

AAR 输出：`riskengine-sdk/build/outputs/aar/`

### ProGuard

SDK 自带 `consumer-rules.pro`，集成方无需额外配置。以下公开 API 混淆后保持不变：

- `com.wsttxm.riskenginesdk.RiskEngine`
- `com.wsttxm.riskenginesdk.RiskEngineConfig`
- `com.wsttxm.riskenginesdk.RiskEngineCallback`
- `com.wsttxm.riskenginesdk.model.RiskReport`
- `com.wsttxm.riskenginesdk.model.RiskLevel`

JNI native 方法自动保留。Release 构建使用 `-repackageclasses 'a'` 做深度混淆。

---

## RiskEngine Server

### 功能

- 接收 SDK 上报数据（明文 / AES-256-GCM 加密）
- 基于指纹关键字段生成设备唯一 ID（SHA-256），追踪设备上报历史
- SpEL 规则引擎动态评估风险，支持热更新，无需重启
- Web 管理后台：仪表盘 / 设备管理 / 上报记录 / 规则管理 / 应用管理
- 多应用隔离接入，每个应用独立 App Key 与加密密钥

### 数据库

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

| 表 | 说明 | 关键字段 |
|----|------|---------|
| app | 接入应用 | appKey (unique), appName, encryptionKey, enabled |
| device | 设备 | deviceId (SHA-256, unique), lastRiskLevel, riskMarked, reportCount |
| device_report | 上报记录 | fingerprintJson, detectionsJson, overallRiskLevel, receivedAt |
| rule_definition | 规则 | ruleName, ruleExpression (SpEL), riskLevel, enabled |
| rule_hit_record | 规则命中 | rule, device, report, hitAt, detail |

### API

#### POST /api/v1/report

**Request Header**

| Header | 必填 | 说明 |
|--------|------|------|
| X-App-Key | Y | 应用密钥 |
| X-Encrypted | N | `true` / `false`，默认 `false` |
| Content-Type | Y | `application/json` |

**请求示例**

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

**响应**

```json
{
  "status": "ok",
  "collect_interval": 1800000,
  "enabled_detectors": [],
  "kill_switch": false
}
```

**错误码**

| HTTP 状态码 | 原因 |
|------------|------|
| 400 | 缺少 X-App-Key / JSON 格式错误 / 解密失败 |
| 401 | 无效 App Key |
| 403 | 应用已禁用 |

### 规则引擎

基于 SpEL，支持运行时增删改规则，无需重启。

**上下文变量**

| 变量 | 类型 | 说明 |
|------|------|------|
| overallRiskLevel | String | 综合风险等级 |
| detections | List | 检测结果 |
| fingerprint | Map | 指纹数据 |
| inconsistentFields | List | 不一致字段 |
| reportCount | int | 设备历史上报次数 |
| riskMarked | boolean | 是否已被手动标记 |

**规则示例**

```
# DEADLY 设备
overallRiskLevel == 'DEADLY'

# Root
detections.?[detectorName == 'RootDetector' and riskLevel == 'HIGH'].size() > 0

# Hook 框架
detections.?[detectorName == 'HookFrameworkDetector' and riskLevel != 'SAFE'].size() > 0

# 指纹不一致 > 2 字段
inconsistentFields.size() > 2

# 高频上报
reportCount > 100

# 模拟器
detections.?[detectorName == 'EmulatorDetector' and riskLevel == 'HIGH'].size() > 0
```

### Web 管理后台

Thymeleaf + Bootstrap 5 构建。

| 页面 | 路径 | 功能 |
|------|------|------|
| 仪表盘 | /dashboard | 设备总数 / 高风险设备数 / 今日上报 / 规则命中统计 |
| 设备管理 | /devices | 设备列表 (分页 / 风险等级筛选) / 设备详情 / 手动标记 |
| 上报记录 | /reports | 上报列表 / 指纹与检测 JSON 查看 |
| 规则管理 | /rules | 规则 CRUD / 启用禁用 |
| 应用管理 | /apps | 应用创建 / 禁用 / Key 与密钥管理 |
| 登录 | /login | 管理员认证 |

### 安全

- API 层 (`/api/**`)：无状态，`X-App-Key` 验证应用身份
- Web 层：Spring Security 表单登录

---

## 部署

### Docker (推荐)

> 前置：Docker 20.10+、Docker Compose v2+

```bash
cd RiskEngineServer
docker-compose up -d
docker-compose logs -f riskengine-server
```

- Web：`http://<host>:8080`
- 账号：`admin` / `admin123`

自定义配置（`docker-compose.yml`）：

```yaml
environment:
  MYSQL_PASSWORD: your_mysql_password
  ADMIN_USERNAME: your_admin
  ADMIN_PASSWORD: your_password
```

停止：

```bash
docker-compose down        # 保留数据
docker-compose down -v     # 清除数据卷
```

### 本地开发

> 前置：JDK 17+

**H2（无需 MySQL）**

```bash
cd RiskEngineServer
./gradlew bootRun --args='--spring.profiles.active=dev'
```

- 应用：`http://localhost:8080`
- H2 Console：`http://localhost:8080/h2-console`（JDBC URL: `jdbc:h2:file:./data/risk_engine;AUTO_SERVER=TRUE`，用户名 `sa`，密码为空）

**MySQL**

```bash
mysql -u root -p -e "CREATE DATABASE risk_engine CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
mysql -u root -p -e "CREATE USER 'risk_engine'@'localhost' IDENTIFIED BY 'risk_engine_pass';"
mysql -u root -p -e "GRANT ALL PRIVILEGES ON risk_engine.* TO 'risk_engine'@'localhost';"

cd RiskEngineServer
./gradlew bootRun
```

**构建 & 测试**

```bash
cd RiskEngineServer
./gradlew bootJar
java -jar build/libs/RiskEngineServer-0.0.1-SNAPSHOT.jar

./gradlew test
```

**环境变量**

| 变量 | 默认值 | 说明 |
|------|--------|------|
| MYSQL_PASSWORD | risk_engine_pass | MySQL 密码 |
| ADMIN_USERNAME | admin | 管理后台用户名 |
| ADMIN_PASSWORD | admin123 | 管理后台密码 |

---

## 加密传输

SDK 与 Server 间支持 AES-256-GCM 加密通道：

```
SDK                                       Server
  │                                          │
  │  1. 采集 + 检测                           │
  │  2. 序列化 JSON                           │
  │  3. AES-256-GCM 加密                     │
  │     - 12 byte random IV                  │
  │     - ciphertext + 16 byte auth tag      │
  │     - concat: IV + ciphertext + tag      │
  │     - Base64 encode                      │
  │                                          │
  │  POST /api/v1/report                     │
  │  X-App-Key: xxx                          │
  │  X-Encrypted: true                       │
  │  Body: Base64(IV + ciphertext + tag)     │
  │ ────────────────────────────────────────► │
  │                                          │  4. Base64 decode
  │                                          │  5. extract IV (first 12 bytes)
  │                                          │  6. AES-256-GCM decrypt
  │                                          │  7. parse JSON
  │                                          │  8. process report
```

密钥管理：

- 每个应用独立 AES-256 密钥 (32 bytes)，在服务端创建应用时生成
- SDK 端通过 `RiskEngineConfig.Builder.encryptionKey(byte[])` 配置
- 未配置密钥时明文上报，服务端兼容两种模式

SDK 端启用：

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
