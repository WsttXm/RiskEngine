#include "detector/widevine_ndk_probe.h"

#include "util/obf_str.h"
#include "util/payload_codec.h"

#include <cstddef>
#include <cstdint>
#include <dlfcn.h>
#include <string>

namespace {

constexpr size_t kMaxPropertyLen = 64;
constexpr int32_t kMediaOk = 0;
constexpr int32_t kMediaMalformed = -10002;

// Widevine DRM UUID: edef8ba9-79d6-4ace-a3c8-27dcd51d21ed
constexpr uint8_t kWidevineUuid[16] = {
    0xed, 0xef, 0x8b, 0xa9,
    0x79, 0xd6,
    0x4a, 0xce,
    0xa3, 0xc8,
    0x27, 0xdc, 0xd5, 0x1d, 0x21, 0xed,
};

struct OpaqueAMediaDrm;

using FnIsCryptoSchemeSupported = bool (*)(const uint8_t uuid[16], const char *mime_type);
using FnCreateByUuid = OpaqueAMediaDrm *(*)(const uint8_t uuid[16]);
using FnGetPropertyString = int32_t (*)(OpaqueAMediaDrm *drm, const char *name, const char **value);
using FnRelease = void (*)(OpaqueAMediaDrm *drm);

struct DlHandleGuard {
    void *handle = nullptr;
    ~DlHandleGuard() {
        if (handle != nullptr) {
            dlclose(handle);
        }
    }
};

struct MediaDrmGuard {
    OpaqueAMediaDrm *drm = nullptr;
    FnRelease release_fn = nullptr;
    ~MediaDrmGuard() {
        if (drm != nullptr && release_fn != nullptr) {
            release_fn(drm);
        }
    }
};

bool copy_bounded_ascii(const char *raw, std::string *out) {
    if (raw == nullptr || out == nullptr) {
        return false;
    }
    out->clear();
    for (size_t i = 0; i <= kMaxPropertyLen; ++i) {
        const auto ch = static_cast<unsigned char>(raw[i]);
        if (ch == '\0') {
            return i > 0;
        }
        if (i == kMaxPropertyLen || ch < 0x20 || ch > 0x7e) {
            out->clear();
            return false;
        }
        out->push_back(static_cast<char>(ch));
    }
    out->clear();
    return false;
}

}  // namespace

std::string native_get_widevine_ndk_probe() {
    const auto lib_name = OBF("libmediandk.so");
    DlHandleGuard lib_guard{};
    lib_guard.handle = dlopen(lib_name.c_str(), RTLD_NOW | RTLD_LOCAL);
    if (lib_guard.handle == nullptr) {
        payload_codec::PayloadBuilder pb(payload_codec::Status::UNSUPPORTED, 0);
        pb.add_header("reason", "mediandk_dlopen_failed");
        return pb.build();
    }

    const auto sym_supported = OBF("AMediaDrm_isCryptoSchemeSupported");
    const auto sym_create = OBF("AMediaDrm_createByUUID");
    const auto sym_get_str = OBF("AMediaDrm_getPropertyString");
    const auto sym_release = OBF("AMediaDrm_release");

    auto fn_supported = reinterpret_cast<FnIsCryptoSchemeSupported>(
            dlsym(lib_guard.handle, sym_supported.c_str()));
    auto fn_create = reinterpret_cast<FnCreateByUuid>(
            dlsym(lib_guard.handle, sym_create.c_str()));
    auto fn_get_str = reinterpret_cast<FnGetPropertyString>(
            dlsym(lib_guard.handle, sym_get_str.c_str()));
    auto fn_release = reinterpret_cast<FnRelease>(
            dlsym(lib_guard.handle, sym_release.c_str()));

    if (fn_supported == nullptr || fn_create == nullptr
            || fn_get_str == nullptr || fn_release == nullptr) {
        payload_codec::PayloadBuilder pb(payload_codec::Status::UNSUPPORTED, 0);
        pb.add_header("reason", "mediandk_symbols_missing");
        return pb.build();
    }

    if (!fn_supported(kWidevineUuid, nullptr)) {
        payload_codec::PayloadBuilder pb(payload_codec::Status::UNSUPPORTED, 0);
        pb.add_header("reason", "widevine_unsupported");
        pb.add_header("supported", "0");
        return pb.build();
    }

    MediaDrmGuard drm_guard{};
    drm_guard.release_fn = fn_release;
    drm_guard.drm = fn_create(kWidevineUuid);
    if (drm_guard.drm == nullptr) {
        payload_codec::PayloadBuilder pb(payload_codec::Status::UNSUPPORTED, 0);
        pb.add_header("reason", "widevine_create_failed");
        pb.add_header("supported", "0");
        return pb.build();
    }

    const auto prop_sec_level = OBF("securityLevel");
    const auto prop_sys_id = OBF("systemId");

    const char *sec_ptr = nullptr;
    int32_t sec_status = fn_get_str(drm_guard.drm, prop_sec_level.c_str(), &sec_ptr);
    std::string sec_level;
    if (sec_status == kMediaOk && !copy_bounded_ascii(sec_ptr, &sec_level)) {
        sec_status = kMediaMalformed;
    }

    const char *sys_ptr = nullptr;
    int32_t sys_status = fn_get_str(drm_guard.drm, prop_sys_id.c_str(), &sys_ptr);
    std::string sys_id;
    if (sys_status == kMediaOk && !copy_bounded_ascii(sys_ptr, &sys_id)) {
        sys_status = kMediaMalformed;
    }

    payload_codec::PayloadBuilder pb(payload_codec::Status::OK, 0);
    pb.add_header("supported", "1");
    pb.add_header_int("sec_status", sec_status);
    if (sec_status == kMediaOk && !sec_level.empty()) {
        pb.add_header("security_level", sec_level);
    }
    pb.add_header_int("sys_status", sys_status);
    if (sys_status == kMediaOk && !sys_id.empty()) {
        pb.add_header("system_id", sys_id);
    }
    return pb.build();
}
