package com.pineone.auth.api.repository;

import com.pineone.auth.api.model.UserToken;
import java.util.Optional;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserTokenRepository extends CrudRepository<UserToken, Long> {

    Optional<UserToken> findByUserSeq(long userSeq);
    Optional<UserToken> findByRefreshToken(String token);

}
