package com.pineone.auth.api.controller.exception.handler;

import com.pineone.auth.api.controller.constant.ApiResult;
import com.pineone.auth.api.controller.constant.ErrorCode;
import com.pineone.auth.api.controller.exception.BusinessException;
import java.util.ArrayList;
import java.util.List;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.TypeMismatchException;
import org.springframework.context.MessageSourceResolvable;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.lang.NonNull;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.validation.FieldError;
import org.springframework.validation.method.ParameterValidationResult;
import org.springframework.web.HttpMediaTypeNotAcceptableException;
import org.springframework.web.HttpMediaTypeNotSupportedException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingPathVariableException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.ServletRequestBindingException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.method.annotation.HandlerMethodValidationException;
import org.springframework.web.multipart.support.MissingServletRequestPartException;
import org.springframework.web.servlet.NoHandlerFoundException;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;
import org.springframework.web.servlet.resource.NoResourceFoundException;

@Slf4j
@Order(Ordered.LOWEST_PRECEDENCE)
@RestControllerAdvice
public class GlobalExceptionHandler extends ResponseEntityExceptionHandler {

    /**
     * 필수 요청 파라미터 누락
     */
    @Override
    protected ResponseEntity<Object> handleMissingServletRequestParameter(MissingServletRequestParameterException ex,
        @NonNull HttpHeaders headers, @NonNull HttpStatusCode status, @NonNull WebRequest request) {
        log.warn("handleMissingServletRequestParameter {}", ex.getMessage());
        String message = String.format("필수 파라미터 '%s'가(이) 누락되었습니다.", ex.getParameterName());

        return createErrorResponseEntity(ErrorCode.BAD_REQUEST, message);
    }

    /**
     * 타입 불일치가 발생한 경우
     */
    @Override
    protected ResponseEntity<Object> handleTypeMismatch(TypeMismatchException ex, HttpHeaders headers,
        HttpStatusCode status, WebRequest request) {
        log.warn("handleTypeMismatch {}", ex.getMessage());
        String message = String.format("파라미터 '%s'의 값 '%s'이(가) 잘못된 타입입니다. 예상되는 타입: '%s'.",
            ex.getPropertyName(),
            ex.getValue(),
            ex.getRequiredType().getSimpleName());

        return createErrorResponseEntity(ErrorCode.BAD_REQUEST, message);
    }

    /**
     * 처리 중 유효성 검사가 실패한 메서드 파라미터에 대한 유효성 검사 오류를 처리합니다.
     * <pre>
     * 이 예외는 {@code @Valid} 또는 {@code @Validated} 애너테이션이 붙은 메서드의 파라미터에서 유효성 검사가 실패했을 때 발생합니다.
     * </pre>
     */
    @Override
    protected ResponseEntity<Object> handleHandlerMethodValidationException(HandlerMethodValidationException ex,
        HttpHeaders headers, HttpStatusCode status, WebRequest request) {
        log.error("handleHandlerMethodValidationException", ex);

        // 유효성 검사 오류 메시지 수집
        List<String> errors = new ArrayList<>();

        List<ParameterValidationResult> results = ex.getValueResults();
        for (ParameterValidationResult result : results) {
            String parameterName = result.getMethodParameter().getParameterName();
            List<MessageSourceResolvable> resolvableErrors = result.getResolvableErrors();
            for (MessageSourceResolvable resolvable : resolvableErrors) {
                errors.add(String.format("'%s' 매개변수 오류: %s", parameterName, resolvable.getDefaultMessage()));
            }
        }
        log.info(errors.toString());

        return createErrorResponseEntity(ErrorCode.BAD_REQUEST, errors.getFirst());
    }

    /**
     * 처리 중 유효성 검사가 실패한 요청 본문 객체에 대한 유효성 검사 오류를 처리합니다.
     * <pre>
     * 이 예외는 {@code @Valid} 또는 {@code @Validated} 애너테이션이 붙은 요청 본문 또는 객체의 유효성 검사가 실패했을 때 발생합니다.
     * </pre>
     */
    @Override
    protected ResponseEntity<Object> handleMethodArgumentNotValid(MethodArgumentNotValidException ex,
        HttpHeaders headers, HttpStatusCode status, WebRequest request) {
        log.error("handleMethodArgumentNotValid", ex);

        // 유효성 검사 실패 메시지를 담을 맵 생성
        List<String> errors = new ArrayList<>();

        // 모든 필드 오류를 가져와서 필드 이름과 오류 메시지를 맵에 저장
        List<FieldError> fieldErrors = ex.getBindingResult().getFieldErrors();
        for (FieldError error : fieldErrors) {
            String errorMessage = String.format("'%s' 필드 오류: %s", error.getField(), error.getDefaultMessage());
            errors.add(errorMessage);
        }
        log.info(String.join(", ", errors));

        return createErrorResponseEntity(ErrorCode.BAD_REQUEST, errors.getFirst());
    }

    /**
     * 요청에 대한 핸들러를 찾을 수 없는 경우
     */
    @Override
    protected ResponseEntity<Object> handleNoHandlerFoundException(NoHandlerFoundException ex, HttpHeaders headers,
        HttpStatusCode status, WebRequest request) {
        log.warn("handleNoHandlerFoundException {}", ex.getMessage());
        return createErrorResponseEntity(ErrorCode.NOT_FOUND);
    }

    /**
     * 지원하지 않는 HTTP 요청 메서드 사용
     */
    @Override
    protected ResponseEntity<Object> handleHttpRequestMethodNotSupported(HttpRequestMethodNotSupportedException ex,
        HttpHeaders headers, HttpStatusCode status, WebRequest request) {
        log.error("handleHttpRequestMethodNotSupported", ex);
        return createErrorResponseEntity(ErrorCode.METHOD_NOT_ALLOWED);
    }

    /**
     * 요청에 대한 리소스가 존재하지 않음
     * <pre>
     * 잘못된 URI를 요청했을 때 발생
     * </pre>
     */
    @Override
    protected ResponseEntity<Object> handleNoResourceFoundException(NoResourceFoundException ex, HttpHeaders headers,
        HttpStatusCode status, WebRequest request) {
        log.error("handleNoResourceFoundException", ex);
        return createErrorResponseEntity(ErrorCode.NOT_FOUND);
    }

    /**
     * 지원하지 않는 미디어 타입 요청
     */
    @Override
    protected ResponseEntity<Object> handleHttpMediaTypeNotSupported(HttpMediaTypeNotSupportedException ex,
        HttpHeaders headers, HttpStatusCode status, WebRequest request) {
        log.error("handleHttpMediaTypeNotSupported", ex);
        return createErrorResponseEntity(ErrorCode.UNSUPPORTED_MEDIA_TYPE);
    }

    /**
     * Accept 헤더에 지원하지 않는 미디어 타입 요청
     */
    @Override
    protected ResponseEntity<Object> handleHttpMediaTypeNotAcceptable(HttpMediaTypeNotAcceptableException ex,
        HttpHeaders headers, HttpStatusCode status, WebRequest request) {
        log.error("handleHttpMediaTypeNotAcceptable", ex);
        return createErrorResponseEntity(ErrorCode.NOT_ACCEPTABLE);
    }

    /**
     * Path Variable 누락
     * <pre>
     * PathVariable 어노테이션의 변수 이름과 URL 템플릿 변수 불일치 시
     * </pre>
     */
    @Override
    protected ResponseEntity<Object> handleMissingPathVariable(MissingPathVariableException ex, HttpHeaders headers,
        HttpStatusCode status, WebRequest request) {
        log.error("handleMissingPathVariable", ex);
        String message = String.format("필수 경로 변수 '%s'가(이) 누락되었습니다.", ex.getVariableName());

        return createErrorResponseEntity(ErrorCode.BAD_REQUEST, message);
    }

    /**
     * 요청 파라미터 바인딩에 실패한 경우
     */
    @Override
    protected ResponseEntity<Object> handleServletRequestBindingException(ServletRequestBindingException ex,
        HttpHeaders headers, HttpStatusCode status, WebRequest request) {
        log.error("handleServletRequestBindingException", ex);
        return createErrorResponseEntity(ErrorCode.BAD_REQUEST);
    }

    /**
     * Part 타입 데이터가 누락된 경우
     * <pre>
     * multipart/form-data 요청의 일부가 손실(can’t be found)되었을 때 발생
     * </pre>
     */
    @Override
    protected ResponseEntity<Object> handleMissingServletRequestPart(MissingServletRequestPartException ex,
        HttpHeaders headers, HttpStatusCode status, WebRequest request) {
        log.error("handleServletRequestBindingException", ex);
        String message = String.format("필수 요청 파트 '%s'가(이) 누락되었습니다.", ex.getRequestPartName());

        return createErrorResponseEntity(ErrorCode.BAD_REQUEST, message);
    }

    /**
     * 잘못된 Request Body 값 요청 하거나 읽을 수 없는 경우 발생
     */
    @Override
    protected ResponseEntity<Object> handleHttpMessageNotReadable(HttpMessageNotReadableException ex,
        HttpHeaders headers, HttpStatusCode status, WebRequest request) {
        log.error("handleHttpMessageNotReadable", ex);

        return createErrorResponseEntity(ErrorCode.BAD_REQUEST);
    }

    /**
     * 비지니스 에러
     */
    @ExceptionHandler(BusinessException.class)
    public ResponseEntity<Object> handleBusinessException(BusinessException ex) {
        log.info("handleBusinessException", ex);
        ErrorCode errorCode = ex.getErrorCode();

        return ResponseEntity.status(errorCode.getHttpStatus())
            .body(ApiResult.response(errorCode, ex.getMessage()));
    }

    @ExceptionHandler(AuthenticationException.class)
    protected ResponseEntity<Object> handleAuthenticationException(AuthenticationException ex) {
        log.info("handleAuthenticationException : {}", ex.getMessage());

        if (ex instanceof UsernameNotFoundException) {
            // 존재하지 않는 아이디
            return createErrorResponseEntity(ErrorCode.UNAUTHORIZED_USER_NOT_FOUND);
        } else if (ex instanceof BadCredentialsException) {
            // 비밀번호 불일치
            return createErrorResponseEntity(ErrorCode.UNAUTHORIZED_LOGIN_FAILED);
        }
        return createErrorResponseEntity(ErrorCode.UNAUTHORIZED);
    }

    @ExceptionHandler(AccessDeniedException.class)
    protected ResponseEntity<Object> handleAccessDeniedException(AccessDeniedException ex) {
        log.info("handleAccessDeniedException : {}", ex.getMessage());

        return createErrorResponseEntity(ErrorCode.FORBIDDEN);
    }

    /**
     * 정의되지 않은 예외
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<Object> handleException(Exception ex) {
        log.error("handleException", ex);
        return createErrorResponseEntity(ErrorCode.INTERNAL_SERVER_ERROR);
    }

    protected ResponseEntity<Object> createErrorResponseEntity(ErrorCode errorCode) {
        return ResponseEntity.status(errorCode.getHttpStatus())
            .body(ApiResult.response(errorCode));
    }

    protected ResponseEntity<Object> createErrorResponseEntity(ErrorCode errorCode, String message) {
        return ResponseEntity.status(errorCode.getHttpStatus())
            .body(ApiResult.response(errorCode, message));
    }

}
