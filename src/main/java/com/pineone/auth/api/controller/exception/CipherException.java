package com.pineone.auth.api.controller.exception;

import com.pineone.auth.api.controller.constant.ErrorCode;

public class CipherException extends BusinessException {
    public CipherException() { super(ErrorCode.INTERNAL_SERVER_ERROR, "암/복호화 모듈 오류"); }
}
