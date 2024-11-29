# 스프링 시큐리티 인증 서버

## 제공 기능
### 1. ID / PW 기반의 회원가입 및 로그인
### 2. OAuth2.0 기반의 회원가입 및 로그인
### 3. JWT 기반 토큰 발급
### 4. 기타
1) 다중 계정 및 다중 로그인 지원
* 같은 사용자가 ID/PW 및 OAuth2.0 회원가입/로그인 시, 별도의 계정으로 처리됨.
* 같은 사용자는 최대 1개의 RefreshToken 정보만 저장됨.
  * 다중 디바이스 로그인 구현 시, 최대 로그인 개수 등 정책 및 수정 필요.
2) AOS / IOS 네이티브 앱 연동 시, 쿠키 기반의 처리
  * 네이티브 앱에서 쿠키 관련 처리 검토 필요. 
  * 브라우저 Client 가 아닌 네이티브 앱 대상 RestAPI 의 경우, RefreshToken 을 Body 에 내리는 방안도 검토 필요.
3) RefreshToken 관련
  * RefreshToken 유효기간 내에는 새로운 AccessToken 만 발급하고, RefreshToken 이 만료된 경우, 에러처리함. (재로그인 플로우)
  * RefreshToken 유효기간 -3일 전에는 새로운 RefreshToken 을 발급하는 등의 정책도 검토 가능.
