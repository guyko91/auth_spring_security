package com.pineone.auth.security.token.jwt;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Map;
import lombok.experimental.UtilityClass;

@UtilityClass
public class RSAKeyUtil {

    private static final String PRIVATE_KEY_PREFIX = "-----BEGIN PRIVATE KEY-----";
    private static final String PRIVATE_KEY_SUFFIX = "-----END PRIVATE KEY-----";
    private static final String PUBLIC_KEY_PREFIX = "-----BEGIN PUBLIC KEY-----";
    private static final String PUBLIC_KEY_SUFFIX = "-----END PUBLIC KEY-----";

    private static final String PRIVATE_PEM_KEY_FILE_NAME = "private_key.pem";
    private static final String PUBLIC_PEM_KEY_FILE_NAME = "public_key.pem";

    /**
     * RSA 키 쌍을 생성하여 PEM 형식으로 반환
     * @return 공개 키와 개인 키 PEM 형식을 담은 Map
     * @throws NoSuchAlgorithmException 알고리즘을 찾을 수 없을 경우
     */
    public static Map<String, String> createKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);  // RSA 키 길이 2048비트

        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        // 키를 PEM 형식으로 변환하여 반환
        String publicKeyPEM = convertToPEM(publicKey.getEncoded(), "PUBLIC KEY");
        String privateKeyPEM = convertToPEM(privateKey.getEncoded(), "PRIVATE KEY");

        return Map.of("publicKey", publicKeyPEM, "privateKey", privateKeyPEM);
    }

    /**
     * JAR 파일 내에서 리소스로부터 개인 키를 읽어옴
     * @return 개인 키
     * @throws IOException 파일 읽기 오류 발생 시
     * @throws NoSuchAlgorithmException 알고리즘을 찾을 수 없을 경우
     * @throws InvalidKeySpecException 키 스펙이 잘못된 경우
     */
    public static PrivateKey getPrivateKey() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        // 리소스에서 PEM 형식 개인 키 읽기
        String privateKeyPEM = readPemFromResource(PRIVATE_PEM_KEY_FILE_NAME);

        // 개인 키 PEM 포맷 처리
        privateKeyPEM = privateKeyPEM
            .replace(PRIVATE_KEY_PREFIX, "")
            .replace(PRIVATE_KEY_SUFFIX, "")
            .replaceAll("\\s", "");
        byte[] encoded = Base64.getDecoder().decode(privateKeyPEM);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        return keyFactory.generatePrivate(keySpec);
    }

    /**
     * JAR 파일 내에서 리소스로부터 공개 키를 읽어옴
     * @return 공개 키
     * @throws IOException 파일 읽기 오류 발생 시
     * @throws NoSuchAlgorithmException 알고리즘을 찾을 수 없을 경우
     * @throws InvalidKeySpecException 키 스펙이 잘못된 경우
     */
    public static PublicKey getPublicKey() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        // 리소스에서 PEM 형식 공개 키 읽기
        String publicKeyPEM = readPemFromResource(PUBLIC_PEM_KEY_FILE_NAME);

        // 공개 키 PEM 포맷 처리
        publicKeyPEM = publicKeyPEM
            .replace(PUBLIC_KEY_PREFIX, "")
            .replace(PUBLIC_KEY_SUFFIX, "")
            .replaceAll("\\s", "");
        byte[] encoded = Base64.getDecoder().decode(publicKeyPEM);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        return keyFactory.generatePublic(new X509EncodedKeySpec(encoded));
    }

    /**
     * PEM 파일을 클래스패스에서 읽어오는 메서드
     * @param fileName 읽을 PEM 파일의 이름
     * @return PEM 파일의 문자열
     * @throws IOException 파일 읽기 오류 발생 시
     */
    private static String readPemFromResource(String fileName) throws IOException {
        try (InputStream inputStream = RSAKeyUtil.class.getClassLoader().getResourceAsStream(fileName)) {
            if (inputStream == null) {
                throw new IOException("Resource not found: " + fileName);
            }
            return new String(inputStream.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    /**
     * 바이트 배열을 PEM 형식의 문자열로 변환
     * @param key 키 바이트 배열
     * @param type "PUBLIC KEY" 또는 "PRIVATE KEY"
     * @return PEM 형식 문자열
     */
    private static String convertToPEM(byte[] key, String type) {
        String encodedKey = Base64.getEncoder().encodeToString(key);
        String formattedKey = "-----BEGIN " + type + "-----\n";
        formattedKey += encodedKey.replaceAll("(.{64})", "$1\n");
        formattedKey += "\n-----END " + type + "-----\n";
        return formattedKey;
    }

}
