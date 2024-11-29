package com.pineone.auth.api.controller.exception;

import com.pineone.auth.api.controller.constant.ErrorCode;

public class NotFoundException extends BusinessException {

    private static final ErrorCode ERROR_CODE = ErrorCode.NOT_FOUND;

    public NotFoundException() {
        super(ERROR_CODE);
    }

    public NotFoundException(String message) {
        super(ERROR_CODE, message);
    }
}
