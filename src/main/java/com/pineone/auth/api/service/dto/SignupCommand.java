package com.pineone.auth.api.service.dto;

public record SignupCommand(
    String id,
    String password,
    String passwordConfirm,
    String name,
    String email
) { }
