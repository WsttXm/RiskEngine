#ifndef RISKENGINE_PERIODIC_MONITOR_H
#define RISKENGINE_PERIODIC_MONITOR_H

#include <jni.h>
#include <string>

/**
 * Background re-verification of the fastest tamper signals.
 *
 * Detection was previously a single snapshot taken during collect(), so a hook
 * installed after that point was never seen: an attacker could simply wait for
 * the check to finish. This runs a small subset of the cheapest, highest-signal
 * checks on a native thread at jittered intervals and latches anything it finds,
 * so a later injection still shows up in the next report.
 *
 * Only a subset runs, deliberately. Full root and emulator scans read hundreds
 * of paths and are far too expensive to repeat; the checks here are the ones
 * that detect live code modification, which is what a post-init attack does.
 *
 * Intervals are jittered so the thread does not become a predictable timing
 * landmark an attacker can synchronise against.
 */
void native_monitor_start(JavaVM *vm);

/** Stops the thread. Safe to call when not started. */
void native_monitor_stop();

/**
 * Returns comma-separated tokens latched since the monitor started, plus the
 * number of completed passes so a caller can tell "clean" from "never ran".
 */
std::string native_monitor_findings();

#endif
