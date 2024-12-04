package com.pineone.auth.security;

import static org.springframework.boot.autoconfigure.security.servlet.PathRequest.toStaticResources;

import com.pineone.auth.security.oauth.CustomOAuth2UserService;
import com.pineone.auth.security.oauth.OAuth2AuthenticationHandler;
import com.pineone.auth.security.token.jwt.JwtAccessDeniedHandler;
import com.pineone.auth.security.token.jwt.JwtAuthenticationEntryPoint;
import com.pineone.auth.security.token.jwt.JwtTokenProvider;
import com.pineone.auth.security.token.jwt.JwtAuthenticationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.cors.CorsConfigurationSource;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final CorsConfigurationSource corsConfigurationSource;

    private final CustomUserDetailsService userDetailsService;
    private final CustomOAuth2UserService customOAuth2UserService;

    private final OAuth2AuthenticationHandler oAuth2AuthenticationHandler;

    private final JwtTokenProvider jwtTokenProvider;
    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
    private final JwtAccessDeniedHandler jwtAccessDeniedHandler;

    private static final String[] FILTER_WHITELIST = {
        "/h2-console/**",
        "/v3/api-docs/**",
        "/swagger-ui/**",
        "/error",
        "/auth/**",
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
                .requestMatchers(FILTER_WHITELIST).permitAll()
                // TODO 인증 없이 접근 가능한 URL 패턴 (회원가입, 로그인 등)
                .requestMatchers(new AntPathRequestMatcher("/auth/**")).permitAll()
                .requestMatchers(new AntPathRequestMatcher("/oauth2/**")).permitAll()
                .anyRequest().authenticated()
            )

            // JWT 설정
            .addFilterBefore(new JwtAuthenticationFilter(jwtTokenProvider, FILTER_WHITELIST), UsernamePasswordAuthenticationFilter.class)
            .exceptionHandling(handler -> handler
                .authenticationEntryPoint(jwtAuthenticationEntryPoint)
                .accessDeniedHandler(jwtAccessDeniedHandler)
            )

            // OAuth2 Client 설정
            .oauth2Login(customConfigurer ->
                customConfigurer
                    .authorizationEndpoint(authorization ->
                        authorization.baseUri("/oauth2/authorization")
                    )
                    .redirectionEndpoint(redirection ->
                        redirection.baseUri("/oauth2/login/code/*")
                    )
                    .userInfoEndpoint(userInfo ->
                        userInfo.userService(customOAuth2UserService)
                    )
                    .successHandler(oAuth2AuthenticationHandler)
                    .failureHandler(oAuth2AuthenticationHandler)
            )
        ;

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() { return new BCryptPasswordEncoder(); }

    @Bean
    public AuthenticationManager authenticationManager(HttpSecurity http) throws Exception {
        return http.getSharedObject(AuthenticationManagerBuilder.class)
            .authenticationProvider(daoAuthenticationProvider())
            .build();
    }

    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider() {
        DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
        daoAuthenticationProvider.setPasswordEncoder(passwordEncoder());
        daoAuthenticationProvider.setUserDetailsService(userDetailsService);
        // 존재하지 않는 사용자 에러를 별도로 처리 (기본값 true : BadCredentialsException)
        daoAuthenticationProvider.setHideUserNotFoundExceptions(false);
        return daoAuthenticationProvider;
    }

}
