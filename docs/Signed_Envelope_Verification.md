# SignedRiskEnvelope 服务端 6 步离线验签指南

本文档定义 RiskEngine v2.0 硬件风控信封（`SignedRiskEnvelope`）的端侧签发格式与服务端 **6 步离线验签规范**（零外部云/HTTP 依赖），并提供 Python 与 Java 跨语言参考实现说明。

---

## 1. 双模式签发策略

| 模式 (`EnvelopeMode`) | 适用场景 | 性能目标 | 证书链绑定 |
| :--- | :--- | :--- | :--- |
| `PERSISTENT_KEY` | 登录、高频风控采样 | 热路径 P95 `< 10ms` | 复用持久化硬件 ECDSA P-256 密钥（`riskengine_envelope_sign_key`，TEE → StrongBox）与缓存证书链 |
| `FRESH_ATTESTATION` | 支付、绑卡、大额转账、注册 | 150–400ms | 使用服务端下发 16–128 字节 `serverChallenge` 现场生成一次性硬件密钥对（`setAttestationChallenge`），签毕 `finally` 立即销毁别名 |
| `SOFTWARE_FALLBACK`（降级输出） | 无硬件 Keystore / 硬件链异常 | `< 5ms` | 显式标注 `attestationMode=SOFTWARE_FALLBACK` 与 `keySecurityLevel=SOFTWARE`，**绝不假冒硬件背书** |

---

## 2. JSON 线协议与规范载荷（Canonical JSON）

### 2.1 `signedEnvelope` JSON 对象（协议 `v=2`，17 字段规范载荷）

既可单独上传 `signedEnvelope` 对象，也可直接上传 `envelope.toReportJson()` 生成的完整 JSON v2 `RiskReport`（包含顶层 `dimensionScores`、`scoreBreakdown`、`recommendedAction`、`hardTriggers`、`confidencePercent` 与 `signedEnvelope` 字段）：

```json
{
  "payload": {
    "v": 2,
    "pkg": "com.host.app",
    "sdk": "2.0.0-SNAPSHOT",
    "scene": "PAYMENT",
    "ts": 1795152000000,
    "monoMs": 8429103,
    "challenge": "<base64url-no-pad-server-nonce>",
    "riskLevel": "SAFE",
    "score": 0,
    "action": "ALLOW",
    "confidence": 100,
    "dimensions": {
      "TAMPERING": 0,
      "PRIVILEGE": 0,
      "ENVIRONMENT": 0,
      "FRAUD_CONTEXT": 0
    },
    "hardTriggers": [],
    "coverage": 100,
    "fpComposite": "<sha256-hex>",
    "fpHardware": "<sha256-hex>",
    "reportSha256": "<sha256-hex-of-canonical-report>"
  },
  "signatureBase64": "<standard-base64-der-ecdsa-sig>",
  "certChainPem": [
    "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
  ],
  "attestationMode": "PERSISTENT_KEY",
  "keySecurityLevel": "TRUSTED_ENVIRONMENT"
}
```

`v=2` 规范载荷关键语义约束：
- `v`：固定为整数 `2`（`SignedRiskEnvelope.PROTOCOL_VERSION`）；
- `score`：标准化 `0–100` 综合风险分（`0` SAFE、`1–29` LOW、`30–59` MEDIUM、`60–84` HIGH、`85–100` DEADLY，存在有效硬触发时保底 `95–100`）；
- `action`：推荐本地处置动作，取值严格限定为 `ALLOW` / `CHALLENGE` / `RESTRICT` / `BLOCK` / `REVIEW`；
- `confidence`：按检测层级加权（`CRITICAL=3`、`FAST=2`、`POSTPONED=1`）计算的评估置信度（`0–100`）；
- `dimensions`：四正交风险维度 `0–100` 子分映射，必须精确包含 `TAMPERING`、`PRIVILEGE`、`ENVIRONMENT`、`FRAUD_CONTEXT` 四个整数字段；
- `hardTriggers`：直接复用 `RiskReport.getHardTriggers()` 权威排序去重列表，保证报告与信封 100% 一致；
- `reportSha256`：剔除顶层 `signedEnvelope` 后的完整 JSON v2 `RiskReport` 规范字节 SHA-256 摘要。

### 2.2 规范 JSON 序列化规则（跨语言位级一致）

签名与 `reportSha256` 均针对 **UTF-8 递归键排序、无多余空白、不转义 `/`** 的规范 JSON 字节计算：
- Java 端：`CanonicalJsonWriter.toCanonicalUtf8Bytes(payload)`
- Python 端：`json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")`

---

## 3. 服务端 6 步离线验签流水线（零外部云依赖）

预检（Step 0）：
- 校验 `signedEnvelope` 必填结构字段（`payload`、`signatureBase64`、`certChainPem`、`attestationMode`）；
- 校验协议版本 `payload.v == 2`（整数且不为布尔值，版本不符直接返回 `UNSUPPORTED_PROTOCOL_VERSION`）；
- 校验 `v=2` 载荷结构：`score` ∈ `[0, 100]`、`action` ∈ `{ALLOW, CHALLENGE, RESTRICT, BLOCK, REVIEW}`、`confidence` ∈ `[0, 100]`、`dimensions` 精确包含 `{TAMPERING, PRIVILEGE, ENVIRONMENT, FRAUD_CONTEXT}` 且各子分均 ∈ `[0, 100]`（违规返回 `ENVELOPE_MALFORMED`）；
- 校验 `attestationMode != SOFTWARE_FALLBACK` 且 `keySecurityLevel != SOFTWARE`（硬件强校验策略下）；
- 上传完整报告时，校验剔除 `signedEnvelope` 后的 JSON v2 规范摘要与 `payload.reportSha256` 一致。

1. **Step 1 — 证书链完整性、约束、有效期与根锚点**：
   - `certChainPem.length >= 2`；
   - 逐级校验证书密码学签名（ECDSA P-256/P-384 或 RSA PKCS#1 v1.5）及根证书自签；
   - 校验 `Issuer DN == Parent Subject DN`、根证书自签发、父证书 `BasicConstraints CA=true`、RFC 5280 §6.1.4 `pathLenConstraint` 及 `KeyUsage.keyCertSign`；
   - 校验每张证书满足 `notBefore <= evalTime <= notAfter`；
   - 校验根证书 SPKI SHA-256 命中内置 Google Hardware Attestation Root 列表。
2. **Step 2 — 吊销检查（CRL / Keybox 黑名单）**：
   - 将链上所有证书序列号同时归一化为十进制与无前导零小写十六进制，比对离线单调 CRL 底线与服务端定期同步的 Google `/attestation/status` 吊销集合。
3. **Step 3 — 根优先 OID `1.3.6.1.4.1.11129.2.1.17` 硬件扩展校验**：
   - **逆序（根 → 叶）扫描**定位权威 OID `.17` 扩展，防止恶意叶子证书注入伪造扩展覆盖中间证书；
   - 严格最小 DER 解码（拒绝非最小长度编码、重复 AuthorizationList tag 与尾部多余字节）；
   - `hwTags`（`teeEnforced`）严格覆盖 `swTags`（`softwareEnforced`）；
   - 校验 `attestationSecurityLevel` 与 `keymasterSecurityLevel` ∈ `{TRUSTED_ENVIRONMENT, STRONG_BOX}`；
   - 校验 `RootOfTrust` 位于 `teeEnforced` 且 `deviceLocked == true`、`verifiedBootState == VERIFIED`；
   - 校验 `attestationApplicationId` 包含预期应用包名与正式发布签名证书 SHA-256。
4. **Step 4 — 挑战绑定、时效窗口与防重放**：
   - 校验 `payload.challenge == base64url_no_pad(expectedChallenge)`；
   - `FRESH_ATTESTATION` 模式下同时校验证书扩展 `attestationChallenge == expectedChallenge`（原始字节精确一致）；
   - 校验 `payload.ts` 落在 `[now - maxAgeMs, now + maxFutureSkewMs]` 窗口内；
   - 使用原子一次消费存储（如 Redis `SET nonce 1 NX EX 300`）拒绝重放。
5. **Step 5 — ECDSA 载荷验签**：
   - 使用叶子证书公钥执行 `SHA256withECDSA(canonicalPayloadUtf8Bytes, signatureBytes)`。
6. **Step 6 — 业务风险决策（`v=2` 标准化 `0–100` 标尺）**：
   - 存在任意 `hardTriggers` → `REJECT`（`POLICY_HARD_TRIGGER`）；
   - `riskLevel` ∈ `{HIGH, DEADLY}`、`action` ∈ `{RESTRICT, BLOCK}` 或 `score >= rejectScoreThreshold`（默认 `60`，对齐 `HIGH` 下限）→ `REJECT`（`POLICY_HIGH_RISK`）；
   - `riskLevel` ∈ `{MEDIUM, UNKNOWN}`、`action` ∈ `{CHALLENGE, REVIEW}`、`confidence < minConfidence`（默认 `70`）或 `coverage < minCoverage`（默认 `80`）→ `STEP_UP`（`POLICY_STEP_UP`，触发二次认证/人工复核）；
   - 否则 → `ALLOW`（`OK`）。

---

## 4. 标准化决策与拒绝码表（Java / Python 1:1 对齐）

| Step | `reasonCode` | `decision` | 含义 |
| :---: | :--- | :---: | :--- |
| 0 | `ENVELOPE_MALFORMED` | `REJECT` | JSON 结构缺失，或 `v=2` 必填字段（`score`/`action`/`confidence`/`dimensions`）类型/取值非法 |
| 0 | `UNSUPPORTED_PROTOCOL_VERSION` | `REJECT` | `payload.v` 协议版本非 `2`（如旧版 `v=1` 或未知协议版本） |
| 0 | `SOFTWARE_FALLBACK_REJECTED` | `REJECT` | 策略要求硬件证明，但端侧上报 `SOFTWARE_FALLBACK` |
| 0 | `REPORT_SHA256_MISMATCH` | `REJECT` | 外层报告规范摘要与 `payload.reportSha256` 不符 |
| 1 | `CERT_CHAIN_TOO_SHORT` | `REJECT` | 证书链长度 `< 2` |
| 1 | `CERT_PARSE_ERROR` | `REJECT` | PEM / 严格 DER 证书解析失败 |
| 1 | `CERT_SIGNATURE_INVALID` | `REJECT` | 证书链逐级签名或根自签失败 |
| 1 | `CERT_ISSUER_MISMATCH` | `REJECT` | Issuer/Subject DN 不连续或根未自签发 |
| 1 | `CERT_CA_CONSTRAINT_INVALID` | `REJECT` | 签发者缺少 CA 约束、`pathLenConstraint` 超限或缺少 `keyCertSign` |
| 1 | `CERT_VALIDITY_EXPIRED` | `REJECT` | 证书尚未生效或已过期 |
| 1 | `ROOT_ANCHOR_UNTRUSTED` | `REJECT` | 根证书 SPKI 未命中 Google 硬件信任根 |
| 2 | `CERT_SERIAL_REVOKED` | `REJECT` | 链上证书序列号命中 Google CRL / 滥用 keybox 黑名单 |
| 3 | `ATTESTATION_EXTENSION_MISSING` | `REJECT` | 缺少 OID `1.3.6.1.4.1.11129.2.1.17` 扩展 |
| 3 | `ATTESTATION_EXTENSION_INVALID` | `REJECT` | OID `.17` DER 编码违规或重复 tag |
| 3 | `ATTESTATION_SECURITY_LEVEL_INVALID` | `REJECT` | 证明/密钥安全级别非 `TEE` / `STRONG_BOX` |
| 3 | `ROOT_OF_TRUST_MISSING` | `REJECT` | 缺少硬件强制的 `RootOfTrust` |
| 3 | `ROOT_OF_TRUST_UNLOCKED` | `REJECT` | Bootloader 已解锁（`deviceLocked=false`） |
| 3 | `ROOT_OF_TRUST_BOOT_UNVERIFIED` | `REJECT` | 启动验证状态非 `VERIFIED` |
| 3 | `APP_ID_PACKAGE_MISMATCH` | `REJECT` | `attestationApplicationId` 或 `payload.pkg` 包名不匹配 |
| 3 | `APP_ID_SIGNATURE_MISMATCH` | `REJECT` | 应用签名证书 SHA-256 不匹配 |
| 4 | `CHALLENGE_MISMATCH` | `REJECT` | `payload.challenge` 与服务端下发挑战不一致 |
| 4 | `ATTESTATION_CHALLENGE_MISMATCH` | `REJECT` | `FRESH_ATTESTATION` 证书扩展挑战不一致 |
| 4 | `NONCE_REPLAYED` | `REJECT` | 挑战 nonce 已被消费（重放攻击） |
| 4 | `ENVELOPE_EXPIRED` | `REJECT` | `payload.ts` 超出允许时效窗口 |
| 5 | `SIGNATURE_INVALID` | `REJECT` | 叶子公钥 `SHA256withECDSA` 载荷验签失败 |
| 6 | `POLICY_HARD_TRIGGER` | `REJECT` | 存在硬触发风险项（如 `tee_grant_chain_split` / `C8:`） |
| 6 | `POLICY_HIGH_RISK` | `REJECT` | 综合风险等级 `HIGH`/`DEADLY`、`action` 为 `RESTRICT`/`BLOCK`，或标准化分数 `>= rejectScoreThreshold`（默认 `60`） |
| 6 | `POLICY_STEP_UP` | `STEP_UP` | `MEDIUM`/`UNKNOWN` 风险、`action` 为 `CHALLENGE`/`REVIEW`，或置信度 `< minConfidence`（默认 `70`）/覆盖率 `< minCoverage`（默认 `80`） |
| — | `OK` | `ALLOW` | 6 步离线校验全部通过 |

---

## 5. 参考实现与命令行用法

### 5.1 独立 Python 验签器（零三方依赖）

参考实现位于 `scripts/verify_risk_envelope.py`，使用纯 Python 3.8+ 标准库完成完整 X.509 签名验证、严格 DER 解析与 `v=2` 6 步校验（输出 JSON `details` 中同步返回经签名验证的 `protocolVersion`、`score`、`action`、`confidence`、`dimensions`、`coverage` 与 `hardTriggers`）：

```bash
python3 scripts/verify_risk_envelope.py \
  --envelope /path/to/report_with_envelope.json \
  --challenge "<base64url-or-hex-server-nonce>" \
  --expected-package "com.host.app" \
  --expected-app-sig "<64-char-release-signing-cert-sha256>" \
  --crl-file /path/to/google_attestation_status.json \
  --min-confidence 70 \
  --min-coverage 80 \
  --reject-score-threshold 60 \
  --require-fresh
```

### 5.2 运行跨语言黄金向量测试

```bash
# Python 独立 6 步验签单测
python3 scripts/test_verify_risk_envelope.py

# Java 独立 6 步验签 + Java↔Python 跨语言 1:1 黄金向量一致性测试
./gradlew :riskengine-sdk:testDebugUnitTest --tests '*EnvelopeOfflineVerifierTest*' --no-daemon
```

> **生产部署提示**：请使用 `scripts/refresh_google_attestation_roots.py` 定期离线更新 Google 硬件信任根与吊销序列号快照，并在服务端将 `InMemoryNonceStore` 替换为带 TTL 的分布式原子存储（如 Redis `SET risk:nonce:<challenge> 1 NX EX 300`）。
