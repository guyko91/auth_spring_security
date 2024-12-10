package com.pineone.auth.security;

import com.pineone.auth.api.service.BidirectionalCipher;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.stereotype.Component;

@Component
public class AESEncryptor implements BidirectionalCipher {

    private static final String ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final String SECRET_KEY_ALGORITHM = "AES";

    // 암호화 메서드
    @Override
    public String encrypt(String base64SecretKey, String value) throws Exception {
        // SecretKeySpec 생성 (256비트 = 32바이트)
        byte[] secretKey = Base64.getDecoder().decode(base64SecretKey);
        SecretKeySpec keySpec = new SecretKeySpec(secretKey, SECRET_KEY_ALGORITHM);

        // IV 초기화 (보안을 위해 SecureRandom 사용)
        byte[] iv = new byte[16];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        // Cipher 인스턴스 생성
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);

        // 암호화 수행
        byte[] encrypted = cipher.doFinal(value.getBytes("UTF-8"));

        // IV와 암호문을 합쳐서 Base64로 인코딩하여 반환
        byte[] combined = new byte[iv.length + encrypted.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(encrypted, 0, combined, iv.length, encrypted.length);

        return Base64.getEncoder().encodeToString(combined);
    }

    // 복호화 메서드
    @Override
    public String decrypt(String base64SecretKey, String base64EncryptedValue) throws Exception {
        // SecretKeySpec 생성
        byte[] secretKey = Base64.getDecoder().decode(base64SecretKey);
        SecretKeySpec keySpec = new SecretKeySpec(secretKey, SECRET_KEY_ALGORITHM);

        // Base64 디코딩
        byte[] combined = Base64.getDecoder().decode(base64EncryptedValue);

        // IV와 암호문 분리
        byte[] iv = new byte[16];
        byte[] encrypted = new byte[combined.length - iv.length];
        System.arraycopy(combined, 0, iv, 0, iv.length);
        System.arraycopy(combined, iv.length, encrypted, 0, encrypted.length);

        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        // Cipher 인스턴스 생성
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);

        // 복호화 수행
        byte[] decrypted = cipher.doFinal(encrypted);

        return new String(decrypted, "UTF-8");
    }

    // 키 생성 유틸리티 메서드
    @Override
    public String generateSecretKey() {
        // 256비트(32바이트) 랜덤 키 생성
        byte[] key = new byte[32];
        new SecureRandom().nextBytes(key);
        return Base64.getEncoder().encodeToString(key);
    }
}
