package com.pineone.auth.security.token;

import java.time.LocalDateTime;

public record TokenDto(
    String token,
    LocalDateTime expireDateTime
) { }
