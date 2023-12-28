package com.cos.security1.controller;

import com.cos.security1.auth.PrincipalDetails;
import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@RequiredArgsConstructor
public class IndexController {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    
    @ResponseBody
    @GetMapping("/test/oauth/login")
    public String testOauthLogin(Authentication authentication, @AuthenticationPrincipal OAuth2User oauth) {

        System.out.println("/test/oauth/login ==================");
        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
        System.out.println("authentication = " + oAuth2User.getAttributes());
        System.out.println(oauth.getAttributes());
        return "OAuth 세션 정보 확인하기";
    }

    @ResponseBody
    @GetMapping("/test/login")
    public String loginTest(Authentication authentication, @AuthenticationPrincipal PrincipalDetails userDetails) {

        System.out.println("/test/login ==================");
        PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
        System.out.println("authentication = " + principalDetails.getUser());

        System.out.println("userDetails = " + userDetails.getUser());
        return "세션 정보 확인하기";
    }

    @GetMapping({"","/"})
    public String index() {

        return "index";
    }

    @GetMapping("/user")
    @ResponseBody
    public String user(@AuthenticationPrincipal PrincipalDetails principalDetails) {

        System.out.println("principalDetails = " + principalDetails.getUser());
        return "user";
    }

    @GetMapping("/admin")
    @ResponseBody
    public String admin() {

        return "admin";
    }

    @GetMapping("/manager")
    @ResponseBody
    public String manager() {

        return "manager";
    }

    @GetMapping("/loginForm")
    public String loginForm() {

        return "loginForm";
    }

    @GetMapping("/joinForm")
    public String joinForm() {

        return "joinForm";
    }

    @PostMapping("/join")
    public String join(User user) {

        user.setRole("ROLE_USER");
        String rawPassword = user.getPassword();
        String encPassword = bCryptPasswordEncoder.encode(rawPassword);
        user.setPassword(encPassword);
        userRepository.save(user);
        return "redirect:/loginForm";
    }

    @GetMapping("/info")
    @ResponseBody
    @Secured("ROLE_ADMIN")
    public String info() {
        return "개인정보";
    }

    @GetMapping("/data")
    @ResponseBody
    @PreAuthorize("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
    public String data() {
        return "데이터정보";
    }
}
