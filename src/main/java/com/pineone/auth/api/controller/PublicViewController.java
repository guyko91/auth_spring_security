package com.pineone.auth.api.controller;

import com.pineone.auth.api.controller.dto.OAuthProviderViewResponse;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
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

}
