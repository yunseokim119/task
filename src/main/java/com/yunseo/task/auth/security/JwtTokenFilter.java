package com.yunseo.task.auth.security;

import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.logging.log4j.util.Strings;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Slf4j(topic = "JwtTokenFilter")
@RequiredArgsConstructor
@Component
public class JwtTokenFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String url = request.getRequestURI();

        // 로그인, 회원가입, 관리자 회원가입 URL에 대해서는 토큰 검증을 건너뛰도록 설정
        if (url.equals("/api/auth/login") || url.equals("/api/auth/signup") || url.equals("/api/auth/admin/signup")) {
            filterChain.doFilter(request, response);  // 로그인, 회원가입, 관리자 회원가입은 토큰 검사 없이 진행
            return;
        }

        // 나머지 URL에 대해서는 토큰 검증 진행
        String tokenValue = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (Strings.isNotBlank(tokenValue)) {
            String token = jwtUtil.substringToken(tokenValue);
            String type = jwtUtil.ACCESS;
            if (validateRefreshTokenUrl(url)) {
                type = jwtUtil.REFRESH;
            }

            if (!jwtUtil.validateToken(token , type)) {
                log.error("인증 실패");
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED , "인증에 실패했습니다.");
            } else {
                log.info("토큰 검증 성공");
                Claims claims = jwtUtil.getUserInfoFromToken(token , type);

                HttpServletRequest httpRequest = (HttpServletRequest) request;
                httpRequest.setAttribute("userId", Long.parseLong(claims.getSubject()));
                httpRequest.setAttribute("email", claims.get("email", String.class));
            }
        } else {
            log.error("토큰이 없습니다.");
            response.sendError(HttpServletResponse.SC_BAD_REQUEST , "토큰이 없습니다.");
        }

        filterChain.doFilter(request, response);
    }

    private boolean validateNotPublicUrl(String url) {
        // 로그인, 회원가입, 관리자 회원가입 URL은 인증 없이 접근 가능하도록 처리
        return !(url.equals("/api/auth/signup") || url.equals("/api/auth/login") || url.equals("/api/auth/admin/signup"));
    }

    // refresh token을 위한 URL인지 확인
    private boolean validateRefreshTokenUrl(String url) {
        return url.equals("/users/refresh-token");
    }
}