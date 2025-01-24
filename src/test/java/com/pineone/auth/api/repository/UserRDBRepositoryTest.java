package com.pineone.auth.api.repository;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

import com.pineone.auth.api.model.User;
import java.util.Optional;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

class UserRDBRepositoryTest extends RDBRepositoryTestSupport {

    @Autowired
    private UserRepository userRepository;

    @DisplayName("ID 에 해당하는 회원 정보가 조회된다.")
    @Test
    void testFindById() {
        // given
        User testUser = User.createNormal("test", "test", "test");

        // when
        entityManager.persist(testUser);
        Optional<User> foundUser = userRepository.findById(testUser.getId());

        // then
        assertThat(foundUser).isPresent();
        assertThat(foundUser.get().getId()).isEqualTo(testUser.getId());
        assertThat(foundUser.get().getName()).isEqualTo(testUser.getName());
    }

    @DisplayName("ID 에 해당하는 회원이 없으면 조회되지 않는다.")
    @Test
    void testNonExistFindUserById() {
        // given
        String nonExistId = "nonExistId";

        // when
        Optional<User> foundUser = userRepository.findById(nonExistId);

        // then
        assertThat(foundUser).isEmpty();
    }

    @DisplayName("ID 에 해당하는 회원 정보가 존재하는 경우 true 를 반환한다.")
    @Test
    void testExistUserById() {
        // given
        User testUser = User.createNormal("test", "test", "test");

        // when
        entityManager.persist(testUser);
        boolean exists = userRepository.existsById(testUser.getId());

        // then
        assertThat(exists).isTrue();
    }

    @DisplayName("ID 에 해당하는 회원 정보가 존재하지 않는 경우 false 를 반환한다.")
    @Test
    void testNonExistUserById() {
        // given
        User testUser = User.createNormal("test", "test", "test");

        // when
        boolean exists = userRepository.existsById(testUser.getId());

        // then
        assertThat(exists).isFalse();
    }

}