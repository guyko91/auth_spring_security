package com.pineone.auth.api.service;

import org.junit.jupiter.api.BeforeEach;
import org.mockito.InjectMocks;
import org.mockito.MockitoAnnotations;

class OTPServiceTest {


    @InjectMocks
    private User2FAService user2FAService;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

}