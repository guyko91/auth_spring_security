package com.pineone.auth.api.repository;

import com.pineone.auth.api.controller.constant.ErrorCode;
import com.pineone.auth.api.controller.exception.BusinessException;
import com.pineone.auth.api.model.User2FA;
import com.pineone.auth.config.AuthProperties;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

@Component
@Transactional
@RequiredArgsConstructor
public class VerificationCodeRepository {

    private static final String VERIFICATION_CODE_KEY_FORMAT = "2FA:%s:%s";
    private static final String DAILY_ATTEMPTS_KEY_FORMAT = "2FA:DAILY_ATTEMPTS:%s";
    private static final String CODE_DATA_CODE_KEY = "code";
    private static final String CODE_DATA_RETRY_COUNT_KEY = "retryCount";

    private final AuthProperties authProperties;
    private final RedisTemplate<String, String> redisTemplate;

    public void createVerificationCode(User2FA user2FA) {

        checkDailyAttempts(user2FA);

        String key = parseVerificationCodeKeyFrom(user2FA);
        int timeoutSeconds = authProperties.getTwoFactorAuth().getVerifyLimitSeconds();
        String randomSixDigitCode = generateRandomSixDigitCode();

        Map<String, String> codeData = Map.of(
            CODE_DATA_CODE_KEY, randomSixDigitCode,
            CODE_DATA_RETRY_COUNT_KEY, "0"
        );

        putRedisDataWith(key, codeData);
        setRedisKeyExpireTime(key, timeoutSeconds, TimeUnit.SECONDS);
    }

    public boolean verifyCode(User2FA user2FA, LocalDateTime verifyDateTime, String userInput) {
        String key = parseVerificationCodeKeyFrom(user2FA);

        // 해시 연산으로 코드와 재시도 횟수 관리
        Map<Object, Object> codeData = getAuthCodeDataWith(key);

        String storedCode = codeData.get(CODE_DATA_CODE_KEY).toString();
        int retryCount = Integer.parseInt(codeData.get(CODE_DATA_RETRY_COUNT_KEY).toString());

        if (isRetryLimitExceeded(retryCount)) {
            throw new BusinessException(ErrorCode.BAD_REQUEST_INVALID_PARAMETER_2FA_RETRY_LIMIT);
        }

        if (isUserInputCodeMatched(userInput, storedCode)) {
            return processAuthCodeMatched(key, user2FA, verifyDateTime);
        }

        return processAuthCodeNotMatched(key, user2FA, verifyDateTime);
    }

    private void checkDailyAttempts(User2FA user2FA) {
        // 일일 인증 시도 횟수 체크
        long userSeq = user2FA.getUserSeq();
        String dailyAttemptsKey = String.format(DAILY_ATTEMPTS_KEY_FORMAT, userSeq);

        long dailyAttempts = getDailyAttemptCountWith(dailyAttemptsKey);

        // 첫 시도일 경우 만료 시간을 오늘 자정으로 설정
        if (dailyAttempts == 1) {
            initializeDailyLimitExpireTime(dailyAttemptsKey);
        }

        // 일일 최대 인증 시도 횟수 체크 (예: 10회)
        boolean dailyLimitExceeded = isDailyLimitExceeded(dailyAttempts);
        if (dailyLimitExceeded) { throw new BusinessException(ErrorCode.UNAUTHORIZED_2FA_DAILY_LIMIT); }
    }

    private Long getDailyAttemptCountWith(String dailyAttemptsKey) {
        Long dailyAttempts = redisTemplate.opsForValue().increment(dailyAttemptsKey, 1);
        if (dailyAttempts == null) { dailyAttempts = 1L; }
        return dailyAttempts;
    }

    private boolean isDailyLimitExceeded(long dailyAttempts) {
        int dailyLimitCount = authProperties.getTwoFactorAuth().getDailyLimitCount();
        return dailyAttempts > dailyLimitCount;
    }

    private void initializeDailyLimitExpireTime(String dailyAttemptsKey) {
        long midnightSeconds = calculateSecondsUntilMidnight();
        redisTemplate.expire(dailyAttemptsKey, midnightSeconds, TimeUnit.SECONDS);
    }

    private String parseVerificationCodeKeyFrom(User2FA user2FA) {
        return String.format(
            VERIFICATION_CODE_KEY_FORMAT,
            user2FA.getUserSeq(),
            user2FA.getAuthMethod()
        );
    }

    private String generateRandomSixDigitCode() {
        SecureRandom random = new SecureRandom();
        int code = random.nextInt(900000) + 100000; // 100000 ~ 999999 사이
        return String.valueOf(code);
    }

    private void putRedisDataWith(String key, Map<String, String> codeData) {
        redisTemplate.opsForHash().putAll(key, codeData);
    }

    private void setRedisKeyExpireTime(String key, int timeoutSeconds, TimeUnit timeUnit) {
        redisTemplate.expire(key, timeoutSeconds, timeUnit);
    }

    private Map<Object, Object> getAuthCodeDataWith(String key) {
        return redisTemplate.opsForHash().entries(key);
    }

    private boolean isRetryLimitExceeded(int retryCount) {
        int verifyLimitCount = authProperties.getTwoFactorAuth().getVerifyLimitCount();
        return retryCount >= verifyLimitCount;
    }

    private boolean isUserInputCodeMatched(String userInput, String storedCode) {
        return StringUtils.hasText(storedCode) && userInput.equals(storedCode);
    }

    private boolean processAuthCodeMatched(String key, User2FA user2FA, LocalDateTime verifyDateTime) {
        redisTemplate.delete(key);
        return user2FA.processVerifyResult(verifyDateTime, true);
    }

    private boolean processAuthCodeNotMatched(String key, User2FA user2FA, LocalDateTime verifyDateTime) {
        addAuthTryCountWith(key);
        return user2FA.processVerifyResult(verifyDateTime, false);
    }

    private void addAuthTryCountWith(String key) {
        redisTemplate.opsForHash().increment(key, CODE_DATA_RETRY_COUNT_KEY, 1);
    }

    private long calculateSecondsUntilMidnight() {
        LocalDateTime now = LocalDateTime.now();
        LocalDateTime midnight = now.toLocalDate().plusDays(1).atStartOfDay();
        return ChronoUnit.SECONDS.between(now, midnight);
    }

}
