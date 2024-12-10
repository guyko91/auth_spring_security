package com.pineone.auth.api.model;

import jakarta.persistence.Id;
import lombok.Getter;
import org.springframework.data.redis.core.RedisHash;

@Getter
@RedisHash(value = "user_auth_tokens", timeToLive = 60)
public class UserAuthToken {

    @Id
    private String id;
    private long userSeq;
    private String uuid;
    private String accessToken;
    private String refreshToken;

    protected UserAuthToken() { }

    private UserAuthToken(long userSeq, String uuid, String accessToken, String refreshToken) {
        this.uuid = uuid;
        this.userSeq = userSeq;
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
    }

    public static UserAuthToken create(long userSeq, String uuid, String accessToken, String refreshToken) {
        return new UserAuthToken(userSeq, uuid, accessToken, refreshToken);
    }
}
