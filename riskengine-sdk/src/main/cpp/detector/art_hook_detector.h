#ifndef RISKENGINE_ART_HOOK_DETECTOR_H
#define RISKENGINE_ART_HOOK_DETECTOR_H

#include <jni.h>
#include <string>

/**
 * Detects Java-method hooking at the ART level.
 *
 * The maps-string and class-presence checks elsewhere are defeated by renaming:
 * an LSPosed build with a stripped module name leaves no matchable text. What a
 * hook cannot avoid is its own mechanism. To intercept a Java method, every
 * Xposed-family framework must either flip that method's access flags to native
 * so the interpreter routes through a bridge, repoint its compiled entry away
 * from libart's code range, or insert a ClassLoader to load its module dex.
 *
 * All three are observable from inside the process with no blocklist, so these
 * checks keep working against renamed and repacked builds.
 */
std::string native_get_art_hook_evidence(JNIEnv *env);

#endif
