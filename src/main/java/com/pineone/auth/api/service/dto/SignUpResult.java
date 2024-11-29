package com.pineone.auth.api.service.dto;

import com.pineone.auth.api.model.User;
import com.pineone.auth.security.token.TokenPairDto;

public record SignUpResult(
    User user,
    TokenPairDto tokenPair
) { }
