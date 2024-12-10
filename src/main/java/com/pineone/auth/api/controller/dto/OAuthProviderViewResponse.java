package com.pineone.auth.api.controller.dto;

public record OAuthProviderViewResponse(
    String registrationId,
    String name,
    String loginUri,
    String description
) { }
