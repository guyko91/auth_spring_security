package com.pineone.auth.security.token;

import java.time.LocalDateTime;

public record TokenDto(
    TokenType type,
    String token,
    LocalDateTime expireDateTime
) { }
