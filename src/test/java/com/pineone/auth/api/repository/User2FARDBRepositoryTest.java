package com.pineone.auth.api.repository;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

import com.pineone.auth.api.model.User2FA;
import java.util.Optional;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

class User2FARDBRepositoryTest extends RDBRepositoryTestSupport {

    @Autowired
    private User2FARepository user2FARepository;

    @DisplayName("사용자 SEQ 에 해당하는 이중인증 정보가 존재하면 조회된다.")
    @Test
    void testExistUserOtpQuery() {
        long userSeq = 1L;
        // given
        User2FA testUser2FA = User2FA.createTOTP(userSeq, "test", "test", "test");

        // when
        entityManager.persist(testUser2FA);
        Optional<User2FA> foundUserOtp = user2FARepository.findByUserSeq(userSeq);

        // then
        assertThat(foundUserOtp).isPresent();
    }

    @DisplayName("사용자 SEQ 에 해당하는 이중인증 정보가 존재하지 않으면 조회되지 않는다.")
    @Test
    void testNonExistUserOtpQuery() {
        long userSeq = 123L;

        // when
        Optional<User2FA> foundUserOtp = user2FARepository.findByUserSeq(userSeq);

        // then
        assertThat(foundUserOtp).isEmpty();
    }

}