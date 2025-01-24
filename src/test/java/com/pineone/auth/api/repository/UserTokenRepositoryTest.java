package com.pineone.auth.api.repository;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

import com.pineone.auth.api.model.UserToken;
import java.time.LocalDateTime;
import java.util.Optional;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.test.context.ActiveProfiles;

@ActiveProfiles("embedded-test")
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
class UserTokenRepositoryTest {

    @Autowired
    private UserTokenRepository userTokenRepository;

    @DisplayName("사용자 SEQ 기반 사용자 토큰 정보를 조회한다. (존재하는 경우)")
    @Test
    void test() {
        // given
        long userSeq = 1L;
        LocalDateTime expiryDate = LocalDateTime.now().plusDays(1);
        UserToken testToken = UserToken.create(userSeq, "test", expiryDate);

        // when
        userTokenRepository.save(testToken);
        Optional<UserToken> userToken = userTokenRepository.findByUserSeq(userSeq);

        // then
        assertThat(userToken).isPresent();
    }

    @DisplayName("사용자 SEQ 기반 사용자 토큰 정보를 조회한다. (존재하지 않는 경우)")
    @Test
    void test2() {
        // given
        long userSeq = 1L;

        // when
        Optional<UserToken> userToken = userTokenRepository.findByUserSeq(userSeq);

        // then
        assertThat(userToken).isEmpty();
    }

    @DisplayName("리프레시 토큰 기반 사용자 토큰 정보를 조회한다. (존재하는 경우)")
    @Test
    void test3() {
        // given
        long userSeq = 1L;
        LocalDateTime expiryDate = LocalDateTime.now().plusDays(1);
        String tokenValue = "test";
        UserToken testToken = UserToken.create(userSeq, tokenValue, expiryDate);

        // when
        userTokenRepository.save(testToken);
        Optional<UserToken> userToken = userTokenRepository.findByRefreshToken(tokenValue);

        // then
        assertThat(userToken).isPresent();
    }

    @DisplayName("리프레시 토큰 기반 사용자 토큰 정보를 조회한다. (존재하지 않는 경우)")
    @Test
    void test4() {
        // given
        String tokenValue = "test";

        // when
        Optional<UserToken> userToken = userTokenRepository.findByRefreshToken(tokenValue);

        // then
        assertThat(userToken).isEmpty();
    }

}