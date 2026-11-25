#ifndef RISKENGINE_APK_SIG_NATIVE_H
#define RISKENGINE_APK_SIG_NATIVE_H

#include <string>

/**
 * Locates the running application's base.apk via /proc/self/maps (falling back
 * to fallback_source_dir when needed) and parses its ZIP EOCD + APK Signing
 * Block (Schemes v2, v3, and v3.1 including v3/v3.1 Proof-of-Rotation lineage)
 * using raw Linux syscalls only (zero libc fopen/fread/zlib).
 *
 * Returns a NativePayloadCodec-formatted wire frame:
 *   Header: status=<OK|RESTRICTED|UNSUPPORTED|ERROR>\terrno=<int>
 *           \treason=<...>\tpath_source=<maps|fallback|none>\tapk_path=<...>
 *           \tfile_size=<uint64>\tschemes=<v2,v3,v3.1>\thas_v2=<0|1>
 *           \thas_v3=<0|1>\thas_v31=<0|1>\tmaps_base_apk_count=<int>
 *   Records:
 *     kind=signer\tscheme=<v2|v3|v3.1>\tindex=<n>[\tmin_sdk=<int>\tmax_sdk=<int>]
 *         \tcert_sha256_hex=<64-hex>\tcert_sha256_b64=<44-b64>
 *     kind=lineage\tscheme=<v3|v3.1>\tsigner_index=<n>\tlevel=<m>
 *         \tcert_sha256_hex=<64-hex>\tcert_sha256_b64=<44-b64>
 */
std::string native_get_apk_signing_info(const char *fallback_source_dir);

/**
 * Parses an explicit APK path via raw syscalls and returns the same
 * NativePayloadCodec wire frame.
 */
std::string native_parse_apk_signing_file(
        const char *apk_path, const char *path_source, int maps_base_apk_count);

#endif  // RISKENGINE_APK_SIG_NATIVE_H
