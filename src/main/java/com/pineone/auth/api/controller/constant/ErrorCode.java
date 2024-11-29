package com.pineone.auth.api.controller.constant;

import java.util.Arrays;
import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.http.HttpStatus;

/**
 * 에러 코드
 * <pre>
 * 응답 코드는 총 8자리
 * XXX(HTTP_STATUS_CODE), XX(SERVICE_CODE), XXX(CUSTOM_CODE)
 *
 * SERVICE_CODE
 * - 00 : 공통
 * - 01 : 인증
 * - 02 : 회원
 * </pre>
 */
@Getter
@AllArgsConstructor
public enum ErrorCode implements ResponseCode{

    // ===============================================================================================================
    // 400 Bad Request
    // ===============================================================================================================
    BAD_REQUEST(HttpStatus.BAD_REQUEST, "40000000", "잘못된 요청"),

    // ===============================================================================================================
    // 401 Unauthorized
    // ===============================================================================================================
    UNAUTHORIZED(HttpStatus.UNAUTHORIZED, "40100000", "인증되지 않은 요청"),
    UNAUTHORIZED_USER_NOT_FOUND(HttpStatus.UNAUTHORIZED, "40100001", "사용자를 찾을 수 없음"),

    UNAUTHORIZED_LOGIN_FAILED(HttpStatus.UNAUTHORIZED, "40101000", "아이디 또는 비밀번호가 일치하지 않음"),
    UNAUTHORIZED_TOKEN_ERROR(HttpStatus.UNAUTHORIZED, "40101100", "토큰 오류"),
    UNAUTHORIZED_TOKEN_EXPIRED(HttpStatus.UNAUTHORIZED, "40101101", "토큰 만료"),
    UNAUTHORIZED_TOKEN_SIGNATURE(HttpStatus.UNAUTHORIZED, "40101102", "토큰 서명 오류"),

    UNAUTHORIZED_ACCESS_TOKEN_BEFORE_EXPIRED(HttpStatus.UNAUTHORIZED, "40101200", "액세스 토큰 만료 이전 요청"),
    UNAUTHORIZED_REFRESH_TOKEN_ERROR(HttpStatus.UNAUTHORIZED, "40101201", "리프레시 토큰이 만료되었거나 유효하지 않음"),
    UNAUTHORIZED_REFRESH_TOKEN_EXPIRED(HttpStatus.UNAUTHORIZED, "40101202", "리프레시 토큰 만료"),
    UNAUTHORIZED_REFRESH_TOKEN_INVALID(HttpStatus.UNAUTHORIZED, "40101203", "리프레시 토큰이 유효하지 않음"),

    // ===============================================================================================================
    // 403 Forbidden
    // ===============================================================================================================
    FORBIDDEN(HttpStatus.FORBIDDEN, "40300000", "접근 권한 없음"),

    // ===============================================================================================================
    // 404 Not Found
    // ===============================================================================================================
    NOT_FOUND(HttpStatus.NOT_FOUND, "40400000", "리소스를 찾을 수 없음"),
    NO_DATA(HttpStatus.NOT_FOUND, "40400001", "데이터 없음"),

    // ===============================================================================================================
    // 405 Method Not Allowed
    // ===============================================================================================================
    METHOD_NOT_ALLOWED(HttpStatus.METHOD_NOT_ALLOWED, "40500000", "해당 메서드를 지원하지 않음"),

    // ===============================================================================================================
    // 406 Not Acceptable
    // ===============================================================================================================
    NOT_ACCEPTABLE(HttpStatus.NOT_ACCEPTABLE, "40600000", "헤더에 명시된 미디어 타입을 제공할 수 없음"),

    // ===============================================================================================================
    // 409 Conflict
    // ===============================================================================================================
    CONFLICT(HttpStatus.CONFLICT, "40900000", "리소스 충돌"),

    // ===============================================================================================================
    // 415 Unsupported Media Type
    // ===============================================================================================================
    UNSUPPORTED_MEDIA_TYPE(HttpStatus.UNSUPPORTED_MEDIA_TYPE, "41500000", "지원하지 않는 미디어 포맷"),

    // ===============================================================================================================
    // 429 Too Many Requests
    // ===============================================================================================================
    TOO_MANY_REQUESTS(HttpStatus.TOO_MANY_REQUESTS, "42900000", "너무 많은 요청"),

    // ===============================================================================================================
    // 500 Internal Server Error
    // ===============================================================================================================
    INTERNAL_SERVER_ERROR(HttpStatus.INTERNAL_SERVER_ERROR, "50000000", "서버 오류"),
    INTERNAL_SERVER_ERROR_EXTERNAL(HttpStatus.INTERNAL_SERVER_ERROR, "50000001", "외부 서버 오류"),

    ;

    private final HttpStatus httpStatus;
    private final String code;
    private final String desc;

    public static ErrorCode valueOf(int httpStatus) {
        return Arrays.stream(values())
            .filter(i -> i.httpStatus.value() == httpStatus)
            .findFirst()
            .orElse(null);
    }

}
