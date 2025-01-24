# 인증서버 

## 사용 기술
- Spring Boot 3.4.0
- Spring Security 6
- Spring Data JPA
- Spring Data Redis
- Spring Thymeleaf

## 제공 기능
### Client (WEB/ APP) 대상 토탈 인증 프로세스 제공
- 로그인 / 회원가입 / OTP 인증 기능 제공
- ID / PW 및 OAuth2.0 기반의 회원 가입 및 로그인 기능 제공 (JWT 토큰 발급)
- TOTP, 이메일, SMS 등 이중인증 기능 제공

## 프로젝트 구조

<details>
<summary>프로젝트 패키지 세부 구조 및 클래스 설명</summary>

```text
src/main/java/com/pineone/
auth
├── AuthApplication.java
├── api
│   ├── controller
│   │   ├── OAuthInfoProvidable.java (OAuth 연동 정보 인터페이스)
│   │   ├── PublicApiController.java (인증 없이 접근 가능한 API)
│   │   ├── PublicViewController.java (인증 없이 접근 가능한 화면 제공 컨트롤러)
│   │   ├── SecureApiController.java (인증이 필요한 API)
│   │   ├── constant
│   │   │   ├── ApiResult.java (API 응답 Wrapper 객체)
│   │   │   ├── ErrorCode.java (API 에러 코드)
│   │   │   ├── ResponseCode.java (API 응답 코드 인터페이스)
│   │   │   └── SuccessCode.java (API 성공 코드)
│   │   ├── dto (클라이언트 요청/응답 DTO 패키지)
│   │   └── exception (API 예외 클래스 및 예외 핸들러 패키지)
│   ├── model
│   │   ├── AuthProvider.java (사용자 인증 유형 Enum)
│   │   ├── BaseTimeEntity.java (JPA Auditing Entity)
│   │   ├── TwoFactorAuthMethod.java (2FA 인증 방식 Enum)
│   │   ├── User.java (사용자 정보 Entity)
│   │   ├── User2FA.java (사용자 2중 인증 정보 Entity)
│   │   ├── UserAuthToken.java (사용자 인증 토큰 정보 Entity)
│   │   └── UserToken.java (사용자 refresh 토큰 정보 Entity)
│   ├── repository (JPA 및 Redis Repository 패키지)
│   ├── service
│   │   ├── AuthFacade.java (인증 서비스 퍼사드 객체)
│   │   ├── BidirectionalCipher.java (양방향 암호화 인터페이스)
│   │   ├── OtpProvidable.java (OTP 인터페이스)
│   │   ├── TwoFactorAuthFactory.java (2FA 인증 객체 팩토리 클래스)
│   │   ├── User2FAService.java (사용자 2FA 인증 서비스)
│   │   ├── UserService.java (사용자 서비스)
│   │   ├── UserTokenService.java (사용자 토큰 서비스)
│   │   ├── dto (서비스 요청/응답 DTO 패키지)
│   │   └── model
│   │       ├── EmailAuthInfoProvidable.java (2FA 이메일 인증 정보 구현체)
│   │       ├── SMSAuthInfoProvidable.java (2FA SMS 인증 정보 구현체)
│   │       ├── TOTPAuthInfoProvidable.java (2FA TOTP 인증 정보 구현체)
│   │       ├── TwoFactorAuthInfoProvidable.java (2FA 인증 정보 인터페이스)
│   └── util
│       └── AESCipher.java (AES 암호화 유틸리티)
├── config
│   ├── AuthProperties.java (설정 프로퍼티 객체)
│   ├── ObjectMapperConfig.java (ObjectMapper 설정)
│   └── TimeZoneConfig.java (타임존 설정)
└── security
    ├── CorsConfig.java (CORS 설정 클래스)
    ├── CustomAuthenticationFilter.java (사용자 인증 필터)
    ├── CustomUserDetailsService.java (ID/PWD 사용자 인증 Security 서비스 구현체)
    ├── SecurityConfig.java (Spring Security 설정 클래스)
    ├── SecurityHandler.java (Spring Security 관련 기능 핸들러)
    ├── ServletAuthHandler.java (HttpServletRequest / HttpServletResponse 관련 기능 핸들러)
    ├── UserPrincipal.java (Spring Security 사용자 Principal 객체)
    ├── oauth
    │   ├── CustomOAuth2UserService.java (OAuth2 사용자 인증 Security 서비스 구현체)
    │   ├── OAuth2AuthenticationHandler.java (OAuth2 인증 성공/실패 핸들러)
    │   ├── OAuth2Provider.java (OAuth2 제공자 정보 Enum)
    │   ├── OAuthProvider.java (OAuth2 연동 정보 제공 구현 클래스)
    │   └── user
    │       ├── AbstractOAuth2User.java (OAuth2 사용자 정보 추상 클래스)
    │       ├── FacebookOAuth2User.java (Facebook OAuth2 사용자 정보 구현 클래스)
    │       ├── GoogleOAuth2User.java (Google OAuth2 사용자 정보 구현 클래스)
    │       ├── KakaoOAuth2User.java (Kakao OAuth2 사용자 정보 구현 클래스)
    │       ├── NaverOAuth2User.java (Naver OAuth2 사용자 정보 구현 클래스)
    │       ├── OAuth2UserInfo.java (OAuth2 사용자 정보 인터페이스)
    │       └── OAuth2UserInfoFactory.java (OAuth2 사용자 객체 생성 팩토리 클래스)
    ├── otp
    │   └── TOtpProvider.java (TOTP 기능 제공 구현체)
    └── token
        ├── TokenClaims.java (토큰 클레임 일급 컬렉션 객체)
        ├── TokenDto.java (토큰 DTO)
        ├── TokenHandler.java (토큰 핸들러)
        ├── TokenPairDto.java (토큰 쌍 DTO)
        ├── TokenProvidable.java (토큰 제공 인터페이스)
        ├── TokenType.java (토큰 유형 Enum)
        ├── TokenAccessDeniedHandler.java (토큰 접근 거부 처리 핸들러)
        ├── TokenAuthenticationEntryPoint.java (미인증 요청 처리 핸들러)
        └── jwt
            ├── JwtProvider.java (JWT 토큰 제공 구현체)
            ├── RSAKeyUtil.java (RSA 키 유틸리티 클래스)
```

</details>


<details>
<summary>application.yml 환경 변수 설정</summary>

```yaml
spring:
  application:
    # 애플리케이션의 이름 (로그인 화면에 표시되는 이름) 
    name: SSO Server

  thymeleaf:
    cache: false
    check-template-location: true
    prefix: classpath:/templates/
    suffix: .html

  security:
    oauth2:
      client:
        # OAuth2 연동 정보 설정
        registration:
          google:
            client-id: ${GOOGLE-CLIENT-ID}
            client-secret: ${GOOGLE-CLIENT-SECRET}
            scope: profile, email
            redirect-uri: "{baseUrl}/oauth2/login/code/{registrationId}"
            authorization-grant-type: authorization_code
            client-name: Google
          facebook:
            client-id: ${FACEBOOK-CLIENT-ID}
            client-secret: ${FACEBOOK-CLIENT-SECRET}
            scope: email, public_profile
            redirect-uri: "{baseUrl}/oauth2/login/code/{registrationId}"
            authorization-grant-type: authorization_code
            client-authentication-method: client_secret_post
            client-name: Facebook
          kakao:
            client-id: ${KAKAO-CLIENT-ID}
            client-secret: ${KAKAO-CLIENT-SECRET}
            scope: profile_nickname, profile_image
            redirect-uri: "{baseUrl}/oauth2/login/code/{registrationId}"
            authorization-grant-type: authorization_code
            client-authentication-method: client_secret_post
            client-name: Kakao
          naver:
            client-id: ${NAVER-CLIENT-ID}
            client-secret: ${NAVER-CLIENT-SECRET}
            scope: name, email, profile_image
            redirect-uri: "{baseUrl}/oauth2/login/code/{registrationId}"
            authorization-grant-type: authorization_code
            client-authentication-method: client_secret_post
            client-name: Naver
        provider:
          # Google 및 FaceBook 과 같은 유명 서비스들은 이미 기본적인 설정이 되어 있어 provider 생략 가능
          google:
            authorization-uri: https://accounts.google.com/o/oauth2/auth
            token-uri: https://accounts.google.com/o/oauth2/token
            user-info-uri: https://www.googleapis.com/oauth2/v3/userinfo
            user-name-attribute: sub
          facebook:
            authorization-uri: https://www.facebook.com/v3.0/dialog/oauth
            token-uri: https://graph.facebook.com/v3.0/oauth/access_token
            user-info-uri: https://graph.facebook.com/me?fields=id,name,email
            user-name-attribute: id
          kakao:
            authorization-uri: https://kauth.kakao.com/oauth/authorize
            token-uri: https://kauth.kakao.com/oauth/token
            user-info-uri: https://kapi.kakao.com/v2/user/me
            user-name-attribute: id
          naver:
            authorization-uri: https://nid.naver.com/oauth2.0/authorize
            token-uri: https://nid.naver.com/oauth2.0/token
            user-info-uri: https://openapi.naver.com/v1/nid/me
            user-name-attribute: response

  datasource:
    url: jdbc:h2:mem:testdb
    driver-class-name: org.h2.Driver
    username: sa
    password:

  # JPA 설정
  jpa:
    hibernate:
      ddl-auto: create-drop
    properties:
      hibernate:
        auto_quote_keyword: true
        format_sql: true
        use_sql_comments: true
        highlight_sql: true
        default_batch_fetch_size: 500
    open-in-view: false
    defer-datasource-initialization: true

  h2:
    console:
      enabled: true
      path: /h2-console

  data:
    redis:
      host: localhost
      port: 6379
      password: ${REDIS-PASSWORD}

# 커스텀 프로퍼티 설정
prop:
  auth:
    # 임시 토큰 만료 밀리초
    temporaryTokenExpMilli: 60000
    # 액세스 토큰 만료 밀리초
    accessTokenExpMilli: 1800000
    # 리프레시 토큰 만료 밀리초
    refreshTokenExpMilli: 864000000
  oauth2:
    # OAuth2 로그인 성공 리다이렉트 URI
    loginSuccessRedirectUri: http://localhost:8080/public/view/success
    # OAuth2 로그인 실패 리다이렉트 URI
    otpRequireRedirectUri: http://localhost:8080/public/view/otp
    # 로그인 성공 토큰 쿼리 파라미터
    loginSuccessTokenQueryParam: tokenKey
  twoFactorAuth:
    # 2FA 인증 활성화 여부 (false 시 2FA 인증 미실시)
    enabled: true 
    # 2FA 인증 방식 (totp, email, sms)
    method: totp
    # 2FA 인증 토큰 만료 일수
    verifyExpDays: 30
    # 2FA 인증 제한 시간 (5분)
    verifyLimitSeconds: 300
    # 2FA 인증 제한 횟수 (5회)
    verifyLimitCount: 5
    # 2FA 인증 일일 제한 횟수 (10회)
    dailyLimitCount: 10

    totp:
      # TOTP 인증 제공자 이름 (인증 앱 등록시 표시되는 이름)
      issuerName: "Auth Server"
      # TOTP QR 코드 이미지 너비
      qrCodeWidth: 200
      # TOTP QR 코드 이미지 높이
      qrCodeHeight: 200

    email:
      # SMTP 프로토콜
      protocol: "smtp"
      # SMTP 호스트
      host: "webmail.pineone.com"
      # SMTP 포트
      port: 587
      # SMTP 사용자 이름
      userName: "help@coolstay.co.kr"
      # SMTP 사용자 비밀번호
      password: "pine1994!!"
      # SMTP 발송자 이메일 설정
      senderEmail: "help@coolstay.co.kr"

    sms:
      # SMS 발송자 번호
      senderNumber: "18334123"
```
</details>

## 인증 흐름 및 OAuth 연동 플로우
* plantuml 플러그인 설치 후 아래 UML 참조
  * uml/auth-flow.puml (전반적인 인증 흐름)
  * uml/oauth-flow.puml (OAuth2 연동 플로우)

## 환경 변수 설정

```text
FACEBOOK-CLIENT-ID={페이스북 클라이언트 ID};
FACEBOOK-CLIENT-SECRET={페이스북 클라이언트 시크릿};
GOOGLE-CLIENT-ID={구글 클라이언트 ID};
GOOGLE-CLIENT-SECRET={구글 클라이언트 시크릿};
KAKAO-CLIENT-ID={카카오 클라이언트 ID};
KAKAO-CLIENT-SECRET={카카오 클라이언트 시크릿};
NAVER-CLIENT-ID={네이버 클라이언트 ID};
NAVER-CLIENT-SECRET={네이버 클라이언트 시크릿};
REDIS-PASSWORD={레디스 비밀번호};
```