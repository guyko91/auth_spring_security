package com.pineone.auth.security;

import com.pineone.auth.config.AuthProperties;
import io.jsonwebtoken.Jwts;
import java.security.PrivateKey;
import java.util.Date;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class TokenProvider {

    private final AuthProperties authProperties;

    public String createToken(Authentication authentication) throws Exception {

        UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();

        String subject = Long.toString(userPrincipal.getId());
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + authProperties.getAuth().getTokenExpirationMilli());
        PrivateKey key = RSAKeyUtil.getPrivateKey();

        return Jwts.builder()
            .setSubject(subject)
            .setIssuedAt(new Date())
            .setExpiration(expiryDate)
            .signWith(key)
            .compact();
    }

}
