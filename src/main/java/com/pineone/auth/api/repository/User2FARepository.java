package com.pineone.auth.api.repository;

import com.pineone.auth.api.model.User2FA;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface User2FARepository extends JpaRepository<User2FA, Long> {

    Optional<User2FA> findByUserSeq(long userSeq);

}
