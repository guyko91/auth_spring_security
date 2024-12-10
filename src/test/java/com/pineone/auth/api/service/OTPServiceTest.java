package com.pineone.auth.api.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.MockitoAnnotations;

class OTPServiceTest {


    @InjectMocks
    private UserOtpService userOtpService;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void testGetSecretKey() {
        String secretKey = userOtpService.getSecretKey();
        assertNotNull(secretKey);
        assertEquals(32, secretKey.length()); // Base32 인코딩된 20 바이트는 32 문자 길이입니다.
    }

    @Test
    void testGetTOTPCode() {
        String secretKey = userOtpService.getSecretKey();
        String totpCode = userOtpService.getTOTPCode(secretKey);
        assertNotNull(totpCode);
        assertEquals(6, totpCode.length()); // 일반적인 TOTP 코드 길이는 6자리입니다.
    }

    @Test
    void testGetQRImageBase64() {
        String googleOTPAuthURL = "otpauth://totp/TestIssuer:test@example.com?secret=JBSWY3DPEHPK3PXP&issuer=TestIssuer";
        int height = 200;
        int width = 200;

        String qrImageBase64 = userOtpService.getQRImageBase64(googleOTPAuthURL, height, width);

        System.out.println("qrImageBase64 = " + qrImageBase64);

        assertNotNull(qrImageBase64);
        assertTrue(qrImageBase64.startsWith("iVBORw0KGgo")); // Base64로 인코딩된 PNG 이미지의 시작 부분
    }

}