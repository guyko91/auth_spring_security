package com.pineone.auth.api.service.dto;

import com.pineone.auth.security.token.TokenPairDto;

public record LoginResult(
    TokenPairDto tokenPair
) { }
