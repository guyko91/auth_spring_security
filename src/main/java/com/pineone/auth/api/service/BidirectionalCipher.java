package com.pineone.auth.api.service;

public interface BidirectionalCipher {

    String encrypt(String secretKey, String plainText);
    String decrypt(String secretKey, String encryptedValue);
    String generateSecretKey();

}
