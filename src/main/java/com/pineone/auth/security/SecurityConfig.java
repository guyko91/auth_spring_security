package com.pineone.auth.security;

import com.pineone.auth.api.service.ServletAuthHandler;
import com.pineone.auth.security.oauth.CustomOAuth2UserService;
import com.pineone.auth.security.oauth.OAuth2AuthenticationHandler;
import com.pineone.auth.security.token.TokenProvider;
import com.pineone.auth.security.token.jwt.JwtAuthenticationFilter;
import com.pineone.auth.security.token.jwt.TokenAccessDeniedHandler;
import com.pineone.auth.security.token.jwt.TokenAuthenticationEntryPoint;
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
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.filter.OncePerRequestFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final CorsConfigurationSource corsConfigurationSource;

    private final CustomUserDetailsService userDetailsService;
    private final CustomOAuth2UserService customOAuth2UserService;

    private final OAuth2AuthenticationHandler oAuth2AuthenticationHandler;

    private final ServletAuthHandler servletAuthHandler;
    private final SecurityProvider securityProvider;

    private final TokenProvider tokenProvider;
    private final TokenAuthenticationEntryPoint tokenAuthenticationEntryPoint;
    private final TokenAccessDeniedHandler tokenAccessDeniedHandler;

    private static final String[] FILTER_WHITELIST = {
        "/h2-console/**",
        "/error",
        "/health",
        "/auth/login/**",
        "/auth/signup/**",
        "/auth/logout/**"
    };

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            // 공통 설정 (CSRF, 세션 관리 등)
            .csrf(AbstractHttpConfigurer::disable)
            .cors(corsConfigurer -> corsConfigurer.configurationSource(corsConfigurationSource))
            .formLogin(formLogin -> formLogin
                .loginPage("/login")
                .loginProcessingUrl("/login")
                .defaultSuccessUrl("/success")
                .permitAll()
            )
            .headers(headers -> headers.frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin))
            .httpBasic(AbstractHttpConfigurer::disable)
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

            // 리소스에 대한 보안 설정
            .authorizeHttpRequests(authorize -> authorize
                .requestMatchers(new AntPathRequestMatcher("/login")).permitAll()
                .requestMatchers(new AntPathRequestMatcher("/signup")).permitAll()
                .requestMatchers(new AntPathRequestMatcher("/error")).permitAll()
                .anyRequest().authenticated()
//                .requestMatchers(toStaticResources().atCommonLocations()).permitAll()
//                // 필터를 적용하지 않을 패턴
//                .requestMatchers(FILTER_WHITELIST).permitAll()
//                // TODO 인증 없이 접근 가능한 URL 패턴 (회원가입, 로그인 등)
//                .requestMatchers(new AntPathRequestMatcher("/auth/login/**")).permitAll()
//                .requestMatchers(new AntPathRequestMatcher("/auth/signup/**")).permitAll()
//                .requestMatchers(new AntPathRequestMatcher("/oauth2/**")).permitAll()
//                .anyRequest().authenticated()
            )

            // 토큰 Filter 설정
//            .addFilterBefore(
//                configureAuthenticationFilter()
//                , UsernamePasswordAuthenticationFilter.class
//            )
//            .exceptionHandling(handler -> handler
//                .authenticationEntryPoint(tokenAuthenticationEntryPoint)
//                .accessDeniedHandler(tokenAccessDeniedHandler)
//            )

            // OAuth2 Client 설정
            .oauth2Login(customConfigurer ->
                customConfigurer
                    .loginPage("/login")
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
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

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

    private OncePerRequestFilter configureAuthenticationFilter() {
        // 인증에 사용할 필터를 명시적으로 생성하여 반환
        return new JwtAuthenticationFilter(
            servletAuthHandler,
            tokenProvider,
            securityProvider,
            FILTER_WHITELIST
        );
    }

}
