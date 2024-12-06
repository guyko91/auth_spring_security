package com.pineone.auth.security;

import java.util.Optional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class SecurityProvider {

    // TODO SpringSecurity 와 순환 참조 발생하여 AuthenticationManager 대신 AuthenticationManagerBuilder 를 사용
    private final AuthenticationManagerBuilder authenticationManagerBuilder;

    /**
     * ID, Password 인증을 수행 한다.
     * @param id
     * @param password
     * @return
     */
    public UserPrincipal authenticateIdPwd(String id, String password) {
        AuthenticationManager authenticationManager = authenticationManagerBuilder.getObject();
        Authentication authentication = authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(id, password));

        SecurityContextHolder.getContext().setAuthentication(authentication);

        return (UserPrincipal) authentication.getPrincipal();
    }

    /**
     * 발급된 토큰은 이미 인증이 완료된 상태이기 때문에, 별도의 authenticate 과정이 필요 없다.
     * @param userPrincipal
     */
    public void authenticateTokenUserPrincipal(UserPrincipal userPrincipal) {
        Authentication authentication = new UsernamePasswordAuthenticationToken(
            userPrincipal, null, userPrincipal.getAuthorities());

        SecurityContextHolder.getContext().setAuthentication(authentication);
    }

    /**
     * SecurityContextHolder 에서 현재 인증된 사용자 정보를 가져온다.
     * @return
     */
    public Optional<UserPrincipal> getCurrentUserPrincipal() {
        final Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null || !authentication.isAuthenticated()) {
            return Optional.empty();
        }

        UserPrincipal principal = (UserPrincipal) authentication.getPrincipal();

        return Optional.of(principal);
    }

}
