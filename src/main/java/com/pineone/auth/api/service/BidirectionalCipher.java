package com.pineone.auth.api.service;

public interface BidirectionalCipher {

    String encrypt(String secretKey, String plainText) throws Exception;
    String decrypt(String secretKey, String encryptedValue) throws Exception;
    String generateSecretKey();

}
