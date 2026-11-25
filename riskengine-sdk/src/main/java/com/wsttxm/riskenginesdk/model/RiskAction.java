package com.wsttxm.riskenginesdk.model;

/**
 * Local business disposition recommended for the host application based on the risk assessment.
 */
public enum RiskAction {
    /** Device posture is safe or informational-only; allow normal flow. */
    ALLOW,
    /** Moderate risk observed; trigger step-up authentication or verification. */
    CHALLENGE,
    /** High risk observed; restrict sensitive operations or downgrade capabilities. */
    RESTRICT,
    /** Severe or hard-triggered compromise (or high risk in payment scene); block operation. */
    BLOCK,
    /** Assessment confidence is insufficient or critical probes failed; route for manual/secondary review. */
    REVIEW
}
