package com.pineone.auth.api.controller;

import com.pineone.auth.api.controller.dto.LoginRequest;
import com.pineone.auth.api.controller.dto.SignUpRequest;
import com.pineone.auth.config.AuthProperties;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

@Controller
@RequiredArgsConstructor
public class ViewController {

    @Value("${otp.serviceName}")
    private String serviceName;

    private final AuthProperties authProperties;

    @GetMapping("/login")
    public String loginPage(Model model) {
        model.addAttribute("serviceName", serviceName);
        return "login";
    }

    @GetMapping("/success")
    public String loginSuccess(Authentication authentication, Model model) {
        // 인증된 사용자 정보 모델에 추가
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        model.addAttribute("username", userDetails.getUsername());
        model.addAttribute("authorities", authentication.getAuthorities());
        return "success";
    }

    @PostMapping("/signup")
    public String signup(@Valid @ModelAttribute SignUpRequest signupRequest) {
        // TODO 회원가입 로직
        return "redirect:/success";
    }

    @PostMapping("/login")
    public String login(@RequestBody LoginRequest loginRequest) {
        // TODO 로그인 로직
        return "redirect:/success";
    }

}
