package com.pineone.auth.api.service.dto;

import com.pineone.auth.security.token.TokenDto;

public record RefreshResult(
    TokenDto newAccessToken
) { }
