package com.pineone.auth.api.controller.utils;

import jakarta.servlet.http.HttpServletRequest;

public class HeaderUtil {

    private static final String AUTHORIZATION_HEADER_KEY = "Authorization";
    private static final String TOKEN_PREFIX = "Bearer ";

    public static String getAccessToken(HttpServletRequest servletRequest) {
        String header = servletRequest.getHeader(AUTHORIZATION_HEADER_KEY);

        if (header == null || !header.startsWith(TOKEN_PREFIX)) {
            return null;
        }

        return header.substring(TOKEN_PREFIX.length());
    }

}
