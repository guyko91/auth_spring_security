package com.pineone.auth.api.repository;

import com.pineone.auth.api.controller.constant.ErrorCode;
import com.pineone.auth.api.controller.exception.BusinessException;
import com.pineone.auth.api.model.User2FA;
import com.pineone.auth.config.AuthProperties;
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
        Map<String, String> codeData = Map.of(
            CODE_DATA_CODE_KEY, user2FA.generateRandomSixDigitCode(),
            CODE_DATA_RETRY_COUNT_KEY, "0"
        );

        redisTemplate.opsForHash().putAll(key, codeData);
        redisTemplate.expire(key, timeoutSeconds, TimeUnit.SECONDS);
    }

    public boolean verifyCode(User2FA user2FA, LocalDateTime verifyDateTime, String userInput) {
        String key = parseVerificationCodeKeyFrom(user2FA);

        // 해시 연산으로 코드와 재시도 횟수 관리
        Map<Object, Object> codeData = redisTemplate.opsForHash().entries(key);

        String storedCode = redisTemplate.opsForValue().get(key);
        int retryCount = Integer.parseInt((String) codeData.get(CODE_DATA_RETRY_COUNT_KEY));

        if (retryCount >= authProperties.getTwoFactorAuth().getVerifyLimitCount()) {
            throw new BusinessException(ErrorCode.BAD_REQUEST_INVALID_PARAMETER_2FA_RETRY_LIMIT);
        }

        if (StringUtils.hasText(storedCode) && userInput.equals(storedCode)) {
            redisTemplate.delete(key);
            return user2FA.processVerifyResult(verifyDateTime, true);
        }

        // 재시도 횟수 증가
        redisTemplate.opsForHash().increment(key, CODE_DATA_RETRY_COUNT_KEY, 1);

        return user2FA.processVerifyResult(verifyDateTime, false);
    }

    private void checkDailyAttempts(User2FA user2FA) {
        // 일일 인증 시도 횟수 체크
        long userSeq = user2FA.getUserSeq();
        String dailyAttemptsKey = String.format(DAILY_ATTEMPTS_KEY_FORMAT, userSeq);

        long dailyAttempts = checkDailyAuthAttempts(dailyAttemptsKey);

        // 첫 시도일 경우 만료 시간을 오늘 자정으로 설정
        if (dailyAttempts == 1) {
            long midnightSeconds = calculateSecondsUntilMidnight();
            redisTemplate.expire(dailyAttemptsKey, midnightSeconds, TimeUnit.SECONDS);
        }

        // 일일 최대 인증 시도 횟수 체크 (예: 10회)
        int dailyAuthLimit = authProperties.getTwoFactorAuth().getDailyLimitCount();
        if (dailyAttempts > dailyAuthLimit) { throw new BusinessException(ErrorCode.UNAUTHORIZED_2FA_DAILY_LIMIT); }
    }

    private Long checkDailyAuthAttempts(String dailyAttemptsKey) {
        Long dailyAttempts = redisTemplate.opsForValue().increment(dailyAttemptsKey, 1);
        if (dailyAttempts == null) { dailyAttempts = 1L; }
        return dailyAttempts;
    }

    private long calculateSecondsUntilMidnight() {
        LocalDateTime now = LocalDateTime.now();
        LocalDateTime midnight = now.toLocalDate().plusDays(1).atStartOfDay();
        return ChronoUnit.SECONDS.between(now, midnight);
    }

    private String parseVerificationCodeKeyFrom(User2FA user2FA) {
        return String.format(
            VERIFICATION_CODE_KEY_FORMAT,
            user2FA.getUserSeq(),
            user2FA.getAuthMethod()
        );
    }

}
