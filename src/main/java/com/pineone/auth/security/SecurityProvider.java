package com.pineone.auth.security;

import com.pineone.auth.api.controller.constant.ErrorCode;
import com.pineone.auth.api.controller.exception.BusinessException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class SecurityProvider {

    private final AuthenticationManager authenticationManager;

    public UserPrincipal createAuthentication(String id, String password) {
        Authentication authentication = authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(id, password));

        SecurityContextHolder.getContext().setAuthentication(authentication);

        return (UserPrincipal) authentication.getPrincipal();
    }

    public UserPrincipal getCurrentUserPrincipal() {
        final Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null || !authentication.isAuthenticated()) {
            throw new BusinessException(ErrorCode.UNAUTHORIZED);
        }

        return (UserPrincipal) authentication.getPrincipal();
    }

}
