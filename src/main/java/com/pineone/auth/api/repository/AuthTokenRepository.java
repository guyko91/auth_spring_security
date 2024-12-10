package com.pineone.auth.api.repository;

import com.pineone.auth.api.model.UserAuthToken;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface AuthTokenRepository extends CrudRepository<UserAuthToken, String> {
}
