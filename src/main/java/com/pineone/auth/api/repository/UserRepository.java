package com.pineone.auth.api.repository;

import com.pineone.auth.api.model.User;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findById(String id);
    boolean existsById(String id);
}
