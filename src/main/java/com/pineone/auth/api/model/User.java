package com.pineone.auth.api.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.LocalDateTime;
import lombok.Getter;

@Getter
@Entity
@Table(name = "tb_user")
public class User {

    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "seq")
    private Long seq;

    @Column(name = "id")
    private String id;

    @Column(name = "password")
    private String password;

    @Column(name = "name")
    private String name;

    @Column(name = "email")
    private String email;

    @Column(name = "email_verified")
    private Boolean emailVerified;

    @Column(name = "2factor_auth_at")
    private LocalDateTime last2factorAuthAt;

    @Enumerated(EnumType.STRING)
    @Column(name = "provider")
    private AuthProvider provider;

    protected User() { }

    private User(Long seq, String id, String password, String name, String email,
        Boolean emailVerified, AuthProvider provider) {
        this.seq = seq;
        this.id = id;
        this.password = password;
        this.name = name;
        this.email = email;
        this.emailVerified = emailVerified;
        this.provider = provider;
    }

    public static User createNormal(String id, String password, String name) {
        return new User(null, id, password, name, null, false, AuthProvider.LOCAL);
    }

    public static User createOAuth2(String id, String name, String email, AuthProvider provider) {
        return new User(null, id, null, name, email, false, provider);
    }
}
