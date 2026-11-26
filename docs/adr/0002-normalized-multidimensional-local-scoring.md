# Normalized Multidimensional Local Risk Scoring Engine

Status: accepted

We replaced the unbounded additive detector score (`DEADLY >= 18` over a ~170+ raw ceiling) and registration-order `dedupeFamilies()` pass with a deterministic 0–100 scoring engine built on family-max aggregation, bounded multi-source corroboration lift, per-dimension Noisy-OR fusion across four orthogonal risk dimensions (`TAMPERING`, `PRIVILEGE`, `ENVIRONMENT`, `FRAUD_CONTEXT`), tiered assessment confidence, explainable `ScoreBreakdown`, `RiskAction` recommendations, and host-configurable local `RiskPolicy`.

## Considered Options

- **Keep unbounded linear summation and add a separate 0–100 helper**: Avoids touching existing raw scores, but perpetuates two conflicting scoring scales, order-dependent deduplication (where an earlier weak finding suppresses a later strong finding in the same family), weak-signal score inflation into `DEADLY`, and score-vs-level contradictions on hard triggers.
- **Pure rule-tree / lookup-table verdict without numeric scoring**: Simple to reason about for fixed scenes, but hard for host apps to customize locally or feed into risk thresholds and UI gauges.
- **Direct switch to 0–100 family-max + Noisy-OR + 4-dimension scoring with `RiskPolicy` before v2.0.0 (chosen)**: Eliminates registration-order bias, bounds weak-signal stacking (pure-weak dimension ceiling ≤ 35), aligns hard triggers with a 95–100 score floor, decouples coverage/confidence from risk score so single non-critical timeouts do not collapse clean devices to `UNKNOWN`, and gives hosts local policy control without requiring a server.

## Consequences

- `RiskReport.getRiskScore()` and `TierReport.getRiskScore()` now operate on a unified `0..100` scale (`0 SAFE`, `1–29 LOW`, `30–59 MEDIUM`, `60–84 HIGH`, `85–100 DEADLY`, Hard Trigger floor `95–100`), while pure informational findings stay at `score = 0` with `RiskLevel.LOW` and `RiskAction.ALLOW`.
- `SignedRiskEnvelope` advances its canonical payload protocol to `v = 2`, carrying normalized `score`, `action`, `confidence`, `dimensions`, and `hardTriggers` sourced directly from `RiskReport`.
- Hosts can override dimension weights, action thresholds, per-family handling, and hard-trigger suppression locally via immutable `RiskPolicy` layered on top of `CollectScene` presets.
