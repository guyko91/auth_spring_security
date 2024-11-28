package com.pineone.auth.security;

import static org.springframework.boot.autoconfigure.security.servlet.PathRequest.toStaticResources;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.cors.CorsConfigurationSource;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final CorsConfigurationSource corsConfigurationSource;

    private static final String[] AUTH_WHITELIST = {
        "/h2-console/**",
        "/v3/api-docs/**",
        "/swagger-ui/**",
        "/test/**",
        "/error",
        "/health",
    };

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            // 공통 설정 (CSRF, 세션 관리 등)
            .csrf(AbstractHttpConfigurer::disable)
            .cors(corsConfigurer -> corsConfigurer.configurationSource(corsConfigurationSource))
            .headers(headers -> headers.frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin))
            .formLogin(AbstractHttpConfigurer::disable)
            .httpBasic(AbstractHttpConfigurer::disable)
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            // 리소스에 대한 보안 설정
            .authorizeHttpRequests(authorize -> authorize
                .requestMatchers(toStaticResources().atCommonLocations()).permitAll()
                // 필터를 적용하지 않을 패턴
                .requestMatchers(AUTH_WHITELIST).permitAll()
                // TODO 인증 없이 접근 가능한 URL 패턴 (회원가입, 로그인 등)
                .requestMatchers(
                    new AntPathRequestMatcher("/api/v1/auth/**"),
                    new AntPathRequestMatcher("oauth2/**")).permitAll()
                .anyRequest().authenticated()
            );

        // TODO 인증 방식에 따른 SecurityConfig 적용
//        jwtSecurityConfig.jwtSecurityFilterChain(http);
//        oAuth2SecurityConfig.oAuth2SecurityFilterChain(http);

        return http.build();
    }

}
