package com.pineone.auth.api.controller;

import com.pineone.auth.api.controller.dto.OAuthProviderViewResponse;
import com.pineone.auth.api.controller.dto.TwoFactorAuthViewRequest;
import com.pineone.auth.api.model.TwoFactorAuthMethod;
import jakarta.validation.Valid;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;

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
    public String otpPage(@RequestBody @Valid TwoFactorAuthViewRequest request, Model model) {

        String tokenKey = request.tokenKey();
        TwoFactorAuthMethod method = TwoFactorAuthMethod.valueOf(request.method());
        boolean isTotp = TwoFactorAuthMethod.TOTP.equals(method);
        String target = isTotp ? "data:image/png;base64, " + request.target() : request.target();

        model.addAttribute("tokenKey", tokenKey);
        model.addAttribute("method", method);
        model.addAttribute("target", target);
        model.addAttribute("limitCount", request.limitCount());
        model.addAttribute("createdAt", request.createdAt());
        model.addAttribute("expireAt", request.expireAt());

        return isTotp ? "otp" : "authCode";
    }
}
