package com.pineone.auth.api.controller.dto;

import jakarta.validation.constraints.NotBlank;

public record SignUpRequest(
    @NotBlank
    String id,
    @NotBlank
    String password,
    @NotBlank
    String name
) { }
