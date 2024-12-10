package com.pineone.auth.api.repository;

import com.pineone.auth.api.model.UserAuthToken;
import java.util.Optional;
import org.springframework.data.keyvalue.repository.KeyValueRepository;

public interface AuthTokenRepository extends KeyValueRepository<UserAuthToken, String> {

    Optional<UserAuthToken> findByUuid(String uuid);
}
