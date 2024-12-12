package com.pineone.auth.security.token;

import com.pineone.auth.security.UserPrincipal;
import java.util.Date;
import java.util.Map;

public class TokenClaims {

    private final Map<String ,Object> claims;

    private static final String EXPIRE_DATE_KEY = "exp";
    private static final String SUBJECT_KEY = "sub";
    private static final String NAME_KEY = "name";
    private static final String ID_KEY = "id";

    private TokenClaims(Map<String, Object> claims) {
        this.claims = claims;
    }

    public static TokenClaims of(Map<String, Object> claims) {
        return new TokenClaims(claims);
    }

    public boolean isTokenExpired(Date expiryDate) {
        Date expiration = (Date) claims.get(EXPIRE_DATE_KEY);
        return expiration.before(expiryDate);
    }

    public UserPrincipal toUserPrincipal() {
        long seq = Long.parseLong((String) claims.get(SUBJECT_KEY));
        String id = (String) claims.get(ID_KEY);
        String name = (String) claims.get(NAME_KEY);
        return UserPrincipal.of(seq, id, name);
    }

}
