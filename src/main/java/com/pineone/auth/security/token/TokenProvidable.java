package com.pineone.auth.security.token;

import com.pineone.auth.security.UserPrincipal;
import java.util.Date;

public interface TokenProvidable {

    TokenDto createToken(UserPrincipal userPrincipal, TokenType tokenType, Date expiryDate);
    TokenClaims validateToken(String tokenString);

}
