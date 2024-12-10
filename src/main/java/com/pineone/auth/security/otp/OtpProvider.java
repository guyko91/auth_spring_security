package com.pineone.auth.security.otp;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.MultiFormatWriter;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.pineone.auth.api.controller.constant.ErrorCode;
import com.pineone.auth.api.controller.exception.BusinessException;
import com.pineone.auth.config.AuthProperties;
import de.taimos.totp.TOTP;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import lombok.RequiredArgsConstructor;
import org.apache.commons.codec.binary.Base32;
import org.apache.commons.codec.binary.Hex;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class OtpProvider {

    private final AuthProperties authProperties;

    // 사용자 마다 고유한 Secret Key 생성
    public String createSecret() {
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[20];
        random.nextBytes(bytes);
        Base32 base32 = new Base32();
        return base32.encodeToString(bytes);
    }

    // Google Authenticator OTP 인증 URL 생성
    public String createOtpAuthUrl(String secretKey, String account) {
        String issuer = authProperties.getOtp().getIssuerName();

        return "otpauth://totp/"
            + URLEncoder.encode(issuer + ":" + account, StandardCharsets.UTF_8).replace("+", "%20")
            + "?secret=" + URLEncoder.encode(secretKey, StandardCharsets.UTF_8).replace("+", "%20")
            + "&issuer=" + URLEncoder.encode(issuer, StandardCharsets.UTF_8).replace("+", "%20");
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
    public boolean verifyOtp(String secretKey, String otpCode) {
        String generatedOTP = getTOTPCode(secretKey);
        return generatedOTP.equals(otpCode);
    }

    // TOTP 코드 생성
    private String getTOTPCode(String secretKey) {
        Base32 base32 = new Base32();
        byte[] bytes = base32.decode(secretKey);
        String hexKey = Hex.encodeHexString(bytes);
        return TOTP.getOTP(hexKey);
    }

}
