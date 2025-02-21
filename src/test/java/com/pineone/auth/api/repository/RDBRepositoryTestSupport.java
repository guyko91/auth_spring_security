package com.pineone.auth.api.repository;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.autoconfigure.orm.jpa.TestEntityManager;

@DataJpaTest
public abstract class RDBRepositoryTestSupport {

    @Autowired
    protected TestEntityManager entityManager;

}
