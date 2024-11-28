package com.pineone.auth.api.model;

import lombok.Getter;

@Getter
public class User {

    private Long id;
    private String password;
    private String name;
    private String email;
    private String imageUrl;
    private Boolean emailVerified = false;
    private AuthProvider provider;

}
