package com.pineone.auth.security.token;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
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

    public static Map<String, String> createKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);

        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        String publicKeyPEM = convertToPEM(publicKey.getEncoded(), "PUBLIC KEY");
        String privateKeyPEM = convertToPEM(privateKey.getEncoded(), "PRIVATE KEY");

        return Map.of("publicKey", publicKeyPEM, "privateKey", privateKeyPEM);
    }

    public static PrivateKey getPrivateKey() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        String privateKeyPEM = new String(Files.readAllBytes(Paths.get(PRIVATE_PEM_KEY_FILE_NAME)));
        privateKeyPEM = privateKeyPEM.replace(PRIVATE_KEY_PREFIX, "")
            .replace(PRIVATE_KEY_SUFFIX, "")
            .replaceAll("\\s", "");
        byte[] encoded = Base64.getDecoder().decode(privateKeyPEM);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(keySpec);
    }

    public static PublicKey getPublicKey() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        String publicKeyPEM = new String(Files.readAllBytes(Paths.get(PUBLIC_PEM_KEY_FILE_NAME)));
        publicKeyPEM = publicKeyPEM.replace(PUBLIC_KEY_PREFIX, "")
            .replace(PUBLIC_KEY_SUFFIX, "")
            .replaceAll("\\s", "");
        byte[] encoded = Base64.getDecoder().decode(publicKeyPEM);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(new X509EncodedKeySpec(encoded));
    }

    private static String convertToPEM(byte[] key, String type) {
        String encodedKey = Base64.getEncoder().encodeToString(key);
        String formattedKey = "-----BEGIN " + type + "-----\n";
        formattedKey += encodedKey.replaceAll("(.{64})", "$1\n");
        formattedKey += "\n-----END " + type + "-----\n";
        return formattedKey;
    }

}
