#ifndef RISKENGINE_PERIODIC_MONITOR_H
#define RISKENGINE_PERIODIC_MONITOR_H

#include <jni.h>
#include <string>

/**
 * Caches NativeMonitorDispatcher jclass (GlobalRef) and static callback jmethodID
 * during JNI_OnLoad so the attached monitor pthread never calls FindClass.
 */
void native_monitor_init_dispatcher(JNIEnv *env, JavaVM *vm);

/**
 * Releases cached dispatcher GlobalRef during JNI_OnUnload.
 * Must be called ONLY after native_monitor_stop() has joined the monitor thread.
 */
void native_monitor_cleanup_dispatcher(JNIEnv *env);

/**
 * Starts the background periodic monitor thread (2-4s initial pass, 20-26s foreground
 * jitter, 120s background backoff, immediate recheck on foreground resume after >10s).
 * Safe to call multiple times (idempotent).
 */
void native_monitor_start(JavaVM *vm);

/** Stops and joins the monitor thread without holding lifecycle locks across join. */
void native_monitor_stop();

/**
 * Notifies the monitor of app foreground/background transitions.
 * Background switches to 120s backoff; foreground resume after >10s triggers an
 * immediate lightweight recheck pass.
 */
void native_monitor_set_background(bool is_background);

/**
 * Returns comma-separated tokens latched since the monitor started, plus the
 * number of completed passes so a caller can tell "clean" from "never ran".
 */
std::string native_monitor_findings();

#endif
