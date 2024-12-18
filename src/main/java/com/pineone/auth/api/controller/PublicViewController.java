package com.pineone.auth.api.controller;

import com.pineone.auth.api.controller.dto.OAuthProviderViewResponse;
import com.pineone.auth.api.model.TwoFactorAuthMethod;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
@RequestMapping("/public/view")
@RequiredArgsConstructor
public class PublicViewController {

    @Value("${spring.application.name}")
    private String applicationName;

    private final OAuthInfoProvidable oAuthProvider;

    @GetMapping("login")
    public String loginPage(Model model) {
        List<OAuthProviderViewResponse> oAuthProviderList = oAuthProvider.getOAuthProviderList();
        model.addAttribute("serviceName", applicationName);
        model.addAttribute("oAuthProviderList", oAuthProviderList);
        return "login";
    }

    @GetMapping("signup")
    public String signupPage() { return "signup"; }

    @GetMapping("success")
    public String loginSuccessPage() { return "success"; }

    @PostMapping("2fa")
    public String otpPage(
        @RequestParam("tokenKey") String tokenKey,
        @RequestParam("target") String target,
        @RequestParam("method") TwoFactorAuthMethod method,
        @RequestParam("limitCount") int limitCount,
        @RequestParam("createdAt") String createdAt,
        @RequestParam("expireAt") String expireAt,
        Model model) {

        boolean isTotp = TwoFactorAuthMethod.TOTP.equals(method);
        target = isTotp ? "data:image/png;base64, " + target : target;

        model.addAttribute("tokenKey", tokenKey);
        model.addAttribute("method", method);
        model.addAttribute("target", target);
        model.addAttribute("limitCount", limitCount);
        model.addAttribute("createdAt", createdAt);
        model.addAttribute("expireAt", expireAt);

        return isTotp ? "otp" : "authCode";
    }
}
