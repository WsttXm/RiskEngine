package com.wsttxm.riskenginesdk;

/**
 * Local collection scene. Changes scoring weights only; every detector still runs.
 */
public enum CollectScene {
    /** Current default informational / actionable split. */
    STANDARD,
    /** Treat emulator and cloud-phone hits as actionable. */
    LOGIN,
    /** LOGIN plus actionable ADB / debugger-adjacent signals. */
    PAYMENT,
    /** Every non-coverage signal is actionable, for local diagnostics. */
    DIAGNOSTIC
}
