package com.pineone.auth.api.model;

import jakarta.persistence.Id;
import lombok.Getter;
import org.springframework.data.redis.core.RedisHash;

@Getter
@RedisHash(value = "user_auth_tokens", timeToLive = 600)
public class UserAuthToken {

    @Id
    private String id;
    private long userSeq;
    private String accessToken;
    private String refreshToken;

    protected UserAuthToken() { }

    private UserAuthToken(String id, long userSeq, String accessToken, String refreshToken) {
        this.id = id;
        this.userSeq = userSeq;
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
    }

    public static UserAuthToken create(String id, long userSeq, String accessToken, String refreshToken) {
        return new UserAuthToken(id, userSeq, accessToken, refreshToken);
    }
}
