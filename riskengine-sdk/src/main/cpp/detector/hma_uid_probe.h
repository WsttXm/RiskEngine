#ifndef RISKENGINE_HMA_UID_PROBE_H
#define RISKENGINE_HMA_UID_PROBE_H

#include <string>

/**
 * Scans [first_uid, last_uid] (max span 10,000) for active tasks using
 * syscall(__NR_getpriority, PRIO_USER, uid) strictly inside util/disposable_child.
 *
 * Returns a NativePayloadCodec frame:
 *   header: status=<OK|RESTRICTED|UNSUPPORTED|ERROR>, errno=<int>,
 *           first_uid=<int>, last_uid=<int>, checked=<int>, active_count=<int>
 *   records: kind=active_uid, uid=<int>
 */
std::string native_scan_active_app_uids(int first_uid, int last_uid);

/**
 * Probes whether a higher-priority seccomp filter intercepts getpriority(PRIO_USER, *)
 * using Linux >= 5.0 SECCOMP_FILTER_FLAG_NEW_LISTENER strictly inside util/disposable_child.
 *
 * Returns a NativePayloadCodec frame:
 *   header: status=<OK|RESTRICTED|UNSUPPORTED|ERROR>, errno=<int>
 *   record: kind=seccomp_uid, install_status=<str>, install_error=<int>,
 *           kernel_major=<int>, kernel_minor=<int>, queried=<int>, notified=<int>,
 *           first_suppressed=<int>, last_suppressed=<int>, query_outcome=<str>,
 *           query_error=<int>, self_notified=<0|1>
 */
std::string native_probe_seccomp_uid_filter(int first_uid, int last_uid);

#endif  // RISKENGINE_HMA_UID_PROBE_H
