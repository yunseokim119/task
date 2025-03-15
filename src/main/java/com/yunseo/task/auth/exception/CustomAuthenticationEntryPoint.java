package com.yunseo.task.auth.exception;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint {

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException)
            throws IOException, ServletException {

        // 관리자 권한이 필요한 요청에 대해서는 403 Forbidden 에러 반환
        if (request.getRequestURI().startsWith("/api/admin") && !request.isUserInRole("ROLE_ADMIN")) {
            response.sendError(HttpServletResponse.SC_FORBIDDEN, "관리자 권한이 필요한 요청입니다. 접근 권한이 없습니다.");
        }
        // 인증되지 않은 사용자에 대해서는 401 Unauthorized 에러 반환
        else {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "인증되지 않은 사용자입니다.");
        }
    }
}