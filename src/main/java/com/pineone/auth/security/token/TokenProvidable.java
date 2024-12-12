package com.pineone.auth.security.token;

import com.pineone.auth.security.UserPrincipal;
import com.pineone.auth.security.token.exception.TokenValidateException;
import java.util.Date;

public interface TokenProvidable {

    TokenDto createToken(UserPrincipal userPrincipal, TokenType tokenType, Date expiryDate);
    TokenClaims validateToken(String tokenString) throws TokenValidateException;

}
