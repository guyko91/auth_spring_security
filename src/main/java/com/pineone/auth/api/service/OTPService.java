package com.pineone.auth.api.service;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.MultiFormatWriter;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.pineone.auth.api.controller.constant.ErrorCode;
import com.pineone.auth.api.controller.exception.BusinessException;
import de.taimos.totp.TOTP;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import org.apache.commons.codec.binary.Base32;
import org.apache.commons.codec.binary.Hex;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class OTPService {

    @Value("${otp.serviceName}")
    private String OTP_ISSUER;

    // 사용자 마다 고유한 Secret Key 생성
    public String getSecretKey() {
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[20];
        random.nextBytes(bytes);
        Base32 base32 = new Base32();
        return base32.encodeToString(bytes);
    }

    // TOTP 코드 생성
    public String getTOTPCode(String secretKey) {
        Base32 base32 = new Base32();
        byte[] bytes = base32.decode(secretKey);
        String hexKey = Hex.encodeHexString(bytes);
        return TOTP.getOTP(hexKey);
    }

    // Google Authenticator OTP 인증 URL 생성
    public String createOtpAuthUrl(String secretKey, String account) {
        return "otpauth://totp/"
            + URLEncoder.encode(OTP_ISSUER + ":" + account, StandardCharsets.UTF_8).replace("+", "%20")
            + "?secret=" + URLEncoder.encode(secretKey, StandardCharsets.UTF_8).replace("+", "%20")
            + "&issuer=" + URLEncoder.encode(OTP_ISSUER, StandardCharsets.UTF_8).replace("+", "%20");
    }

    // QR Code 이미지 생성
    public String getQRImageBase64(String googleOTPAuthURL, int height, int width) {
        try {
            BitMatrix bitMatrix = new MultiFormatWriter().encode(googleOTPAuthURL, BarcodeFormat.QR_CODE, width, height);

            ByteArrayOutputStream str = new ByteArrayOutputStream();
            MatrixToImageWriter.writeToStream(bitMatrix, "PNG", str);

            return Base64.getEncoder().encodeToString(str.toByteArray());
        }catch (WriterException | IOException e) {
            throw new BusinessException(ErrorCode.INTERNAL_SERVER_ERROR, "QR 코드 생성에 실패했습니다.");
        }
    }

    // OTP 코드 검증
    public boolean verifyOTP(String secretKey, String otpCode) {
        String generatedOTP = getTOTPCode(secretKey);
        return generatedOTP.equals(otpCode);
    }

}
