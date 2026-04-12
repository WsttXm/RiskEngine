package org.wstt.riskengineserver.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * AES-256-GCM加解密服务, 与SDK端DataEncryptor保持一致
 * 数据格式: Base64(IV[12bytes] + ciphertext + tag)
 */
@Service
public class EncryptionService {

    private static final Logger log = LoggerFactory.getLogger(EncryptionService.class);
    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 128;

    /**
     * 解密SDK上报的加密数据
     * @param encryptedBase64 Base64编码的加密数据(IV + ciphertext)
     * @param keyBase64 Base64编码的AES-256密钥
     * @return 解密后的明文JSON
     */
    public String decrypt(String encryptedBase64, String keyBase64) {
        try {
            byte[] key = Base64.getDecoder().decode(keyBase64);
            byte[] data = Base64.getDecoder().decode(encryptedBase64);

            byte[] iv = new byte[GCM_IV_LENGTH];
            System.arraycopy(data, 0, iv, 0, iv.length);

            Cipher cipher = Cipher.getInstance(ALGORITHM);
            GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), spec);

            byte[] plaintext = cipher.doFinal(data, iv.length, data.length - iv.length);
            return new String(plaintext, StandardCharsets.UTF_8);
        } catch (Exception e) {
            log.error("解密失败", e);
            return null;
        }
    }

    /**
     * 生成随机AES-256密钥, Base64编码
     */
    public String generateKey() {
        byte[] key = new byte[32];
        new SecureRandom().nextBytes(key);
        return Base64.getEncoder().encodeToString(key);
    }
}
