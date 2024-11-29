package com.pineone.auth.api.controller.constant;

import org.springframework.http.HttpStatus;

public interface ResponseCode {

    String name();
    HttpStatus getHttpStatus();
    String getCode();
    String getDesc();
}
