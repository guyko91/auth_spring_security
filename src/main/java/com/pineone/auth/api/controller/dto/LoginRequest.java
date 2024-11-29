package com.pineone.auth.api.controller.dto;

import jakarta.validation.constraints.NotBlank;

public record LoginRequest(
    @NotBlank
    String id,
    @NotBlank
    String password
) { }
