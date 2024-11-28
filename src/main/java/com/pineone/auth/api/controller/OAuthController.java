package com.pineone.auth.api.controller;

import com.pineone.auth.security.oauth.OAuth2Service;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;

@Controller
@RequiredArgsConstructor
public class OAuthController {

    private final OAuth2Service oAuth2Service;



}
