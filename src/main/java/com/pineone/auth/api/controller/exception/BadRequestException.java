package com.pineone.auth.api.controller.exception;

import com.pineone.auth.api.controller.constant.ErrorCode;

public class BadRequestException extends BusinessException {

    private static final ErrorCode ERROR_CODE = ErrorCode.BAD_REQUEST;

    public BadRequestException() {
        super(ERROR_CODE);
    }

    public BadRequestException(String message) {
        super(ERROR_CODE, message);
    }
}
