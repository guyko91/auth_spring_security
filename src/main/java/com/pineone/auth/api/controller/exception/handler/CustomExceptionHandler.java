package com.pineone.auth.api.controller.exception.handler;

import com.pineone.auth.api.controller.constant.ErrorCode;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.annotation.Order;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@Slf4j
@Order(1)
@RestControllerAdvice
public class CustomExceptionHandler extends GlobalExceptionHandler {

    @Override
    protected ResponseEntity<Object> createErrorResponseEntity(ErrorCode errorCode) {
        return super.createErrorResponseEntity(errorCode);
    }

    @Override
    protected ResponseEntity<Object> createErrorResponseEntity(ErrorCode errorCode, String message) {
        return super.createErrorResponseEntity(errorCode, message);
    }
}
