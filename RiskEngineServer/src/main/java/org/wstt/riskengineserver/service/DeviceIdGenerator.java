package org.wstt.riskengineserver.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.wstt.riskengineserver.dto.CollectorResultDTO;
import org.wstt.riskengineserver.dto.DeviceFingerprintDTO;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Map;
import java.util.StringJoiner;

/**
 * 设备ID生成器 - 从指纹关键字段生成稳定的设备唯一标识
 */
@Service
public class DeviceIdGenerator {

    private static final Logger log = LoggerFactory.getLogger(DeviceIdGenerator.class);

    /** 用于生成设备ID的关键指纹字段, 按优先级排列 */
    private static final String[] KEY_FIELDS = {
            "android_id", "drm_id", "build_props", "boot_id"
    };

    /**
     * 从设备指纹生成唯一设备ID (SHA-256 hash)
     */
    public String generateDeviceId(DeviceFingerprintDTO fingerprint) {
        if (fingerprint == null || fingerprint.getResults() == null) {
            return "unknown_" + System.currentTimeMillis();
        }

        Map<String, CollectorResultDTO> results = fingerprint.getResults();
        StringJoiner joiner = new StringJoiner("|");

        for (String field : KEY_FIELDS) {
            CollectorResultDTO result = results.get(field);
            if (result != null && result.getCanonicalValue() != null
                    && !result.getCanonicalValue().isEmpty()) {
                joiner.add(field + "=" + result.getCanonicalValue());
            }
        }

        String raw = joiner.toString();
        if (raw.isEmpty()) {
            // 回退: 使用所有可用的canonical values
            StringJoiner fallback = new StringJoiner("|");
            results.forEach((key, val) -> {
                if (val.getCanonicalValue() != null && !val.getCanonicalValue().isEmpty()) {
                    fallback.add(key + "=" + val.getCanonicalValue());
                }
            });
            raw = fallback.toString();
        }

        return sha256(raw);
    }

    private String sha256(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : hash) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            log.error("SHA-256计算失败", e);
            return "error_" + System.currentTimeMillis();
        }
    }
}
