# RiskEngine

On-device Android security and fraud risk assessment SDK that collects environment evidence, evaluates threat domains, and produces an explainable local risk decision without requiring a backend service.

## Language

### Core Architecture

**Detection Domain**:
A cohesive top-level security or fraud inspection category (such as root detection, hook framework detection, or hardware trust root verification) that aggregates one or more underlying probes into a single domain verdict.
_Avoid_: Check group, module, scanner

**Evidence Item**:
A structured, immutable atomic finding recording what was observed, where it was observed, which inspection layers corroborated it, and its evidential strength.
_Avoid_: Raw detail, token string, log entry

**Evidence Family**:
An orthogonal root-cause classification shared across detection domains so that multiple detectors observing the same underlying compromise do not double-count risk.
_Avoid_: Risk tag, signal type, dedupe key

**Correlation Rule**:
A cross-domain inference rule that recognizes higher-order attack patterns (such as spoofed verified boot or voice-phishing screen control) when independent signals combine.
_Avoid_: Combo detector, bonus rule

### Scoring & Decision

**Risk Dimension**:
One of the four orthogonal axes—Tampering, Privilege, Environment, and Fraud Context—along which device risk is independently scored before contributing to the overall risk score.
_Avoid_: Risk bucket, threat group, sub-category

**Hard Trigger**:
A high-confidence, indisputable compromise indicator that immediately elevates the overall risk level to deadly and floors the risk score regardless of other signals.
_Avoid_: Instant-kill flag, override token, auto-ban rule

**Score Breakdown**:
The auditable, item-by-item explanation showing how each evidence family, corroboration lift, correlation rule, and hard trigger contributed to the final risk score.
_Avoid_: Score trace, debug log, point ledger

**Risk Action**:
The local business disposition recommended for the host application (such as allow, challenge, restrict, block, or review) derived from the risk assessment and active policy.
_Avoid_: Verdict status, enforcement hook, kill switch

**Risk Policy**:
A host-supplied local rule set that configures dimension weights, decision thresholds, and per-family overrides on top of a built-in scene preset.
_Avoid_: Server rule, scoring config, threshold map

**Collection Scene**:
A built-in business context preset (standard, login, payment, or diagnostic) that adjusts how detected evidence is weighted and acted upon without changing which probes execute.
_Avoid_: Scan mode, profile, run level

**Corroboration Lift**:
A bounded evidential boost applied when the same evidence family is independently confirmed across multiple inspection layers or distinct detection domains.
_Avoid_: Double counting, bonus multiplier

**Assessment Confidence**:
A tiered measure of how completely and reliably the critical, fast, and postponed detection domains executed during a scan, evaluated independently from the risk score.
_Avoid_: Coverage score, trust score, health rate
