package com.pineone.auth.api.controller.exception;

import com.pineone.auth.api.controller.constant.ErrorCode;

public class AlreadyExistException extends BusinessException {

    private static final ErrorCode ERROR_CODE = ErrorCode.CONFLICT;

    public AlreadyExistException() {
        super(ERROR_CODE);
    }

    public AlreadyExistException(String message) {
        super(ERROR_CODE, message);
    }
}
