# SSO 인증 서버

## 기술 스택
- Spring Boot 3.4.0
- Spring Security 6
- Spring Data JPA
- Spring Data Redis
- Spring Thymeleaf

## 제공 기능
### 1. Client (WEB/ APP) 대상 토탈 인증 프로세스 제공
- 로그인 / 회원가입 / OTP 인증 화면 제공 (SSR - thymeleaf)
- ID / PW 기반의 회원 가입 및 로그인
- OAuth2.0 기반의 회원 가입 및 로그인
- JWT 기반의 토큰 발급
- TOTP 2차 인증 기능 제공

### 2. 발급된 토큰 기반 인증 모듈 제공
- 작성 필요 (TODO)

### 3. TODO
#### 1) 토큰 기반 서비스/API 별 호출 권한 관리
- 발급된 JWT access token 을 통한 내부 타 서비스 API 호출 시 권한 체크 방식 (in 인증 모듈 라이브러리)

#### 2) OTP 인증 플로우 고도화
- OTP 인증 시나리오 고도화 (인증 주기, 인증 흐름 등)
- OTP 를 사용하지 않는 서비스의 경우 yml 설정을 통한 비활성화 처리

#### 3) 기타
- body 나 header 로 주고받는 토큰에 대한 보안 검토
- 로그인 / 회원가입 성공 후, client 에 postMessage 를 통한 토큰 전달 방식 검토
- 각 모듈 테스트 코드
- application.yml 환경별 분리 (local, dev, stg, prod)
- 프론트엔드 코드 리팩토링 필요
- 다른 방식의 2FA 인증 방식 추가 (SMS, 이메일 등등)