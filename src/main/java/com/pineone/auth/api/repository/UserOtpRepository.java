package com.pineone.auth.api.repository;

import com.pineone.auth.api.model.UserOtp;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserOtpRepository extends JpaRepository<UserOtp, Long> {

    Optional<UserOtp> findByUserSeq(long userSeq);

}
