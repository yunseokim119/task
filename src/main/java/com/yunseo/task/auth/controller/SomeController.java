package com.yunseo.task.auth.controller;

import com.yunseo.task.auth.entity.AuthUser;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SomeController {

    @GetMapping("/some-endpoint")
    public String someMethod() {
        // 현재 인증된 사용자 정보 가져오기
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        AuthUser authUser = (AuthUser) authentication.getPrincipal();

        // 역할 정보 가져오기
        String role = authUser.getRole().name();

        return "사용자의 역할은 " + role + "입니다.";
    }
}