package com.pineone.auth.api.repository;

import com.pineone.auth.api.model.User;
import java.util.Optional;

public interface UserRepository {

    Optional<User> findByEmail(String email);
    boolean existsByEmail(String email);

}
