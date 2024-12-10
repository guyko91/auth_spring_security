package com.pineone.auth.api.controller.dto;

import com.pineone.auth.api.service.dto.SignupCommand;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

public record SignUpRequest(
    @NotBlank
    String id,

    @NotBlank
    String password,

    @NotBlank
    String passwordConfirm,

    @NotBlank
    String name,

    @Email
    String email
) {
    public SignupCommand toSignupCommand() {
        return new SignupCommand(id(), password(), passwordConfirm(), name(), email());
    }
}
