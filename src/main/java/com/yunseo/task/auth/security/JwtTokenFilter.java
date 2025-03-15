package com.yunseo.task.auth.security;

import com.yunseo.task.auth.entity.Role;
import com.yunseo.task.auth.entity.User;
import com.yunseo.task.auth.impl.UserDetailsImpl;
import com.yunseo.task.auth.repository.UserRepository;
import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collections;
import java.util.Optional;

@Slf4j(topic = "JwtTokenFilter")
@RequiredArgsConstructor
@Component
public class JwtTokenFilter extends OncePerRequestFilter {

    private final JwtTokenProvider jwtTokenProvider;
    private final UserRepository userRepository;

    private static final String LOGIN_URL = "/api/auth/login";
    private static final String SIGNUP_URL = "/api/auth/signup";
    private static final String ADMIN_SIGNUP_URL = "/api/auth/admin/signup";
    private static final String REFRESH_TOKEN_URL = "/users/refresh-token";

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String url = request.getRequestURI();

        // 1️⃣ 인증이 필요 없는 URL (permitAll() 설정된 URL)
        if (isPublicUrl(url)) {
            filterChain.doFilter(request, response);
            return;
        }

        // 2️⃣ Authorization 헤더에서 토큰 추출
        String tokenValue = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (tokenValue == null || tokenValue.isBlank()) {
            log.warn("🚨 Authorization 헤더가 없습니다.");
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "유효한 토큰이 필요합니다.");
            return;
        }

        log.debug("🔹 Authorization Header Value: {}", tokenValue);

        // 3️⃣ resolveToken 호출 (Bearer 제거)
        String token = jwtTokenProvider.resolveToken(tokenValue);

        if (token == null) {
            log.error("🚨 토큰 추출 실패 - Bearer 제거 후 null 반환됨. 원본 값: {}", tokenValue);
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "인증 실패: 유효한 토큰을 제공해야 합니다.");
            return;
        }

        // 4️⃣ Refresh Token 요청인지 확인
        boolean isRefreshRequest = isRefreshTokenUrl(url);

        // 5️⃣ Access Token 또는 Refresh Token 검증
        if (!jwtTokenProvider.validateToken(token, !isRefreshRequest)) {
            log.error("🚨 인증 실패 - 토큰 검증 실패. JWT: {}", token);
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "인증에 실패했습니다.");
            return;
        }

        log.info("✅ 토큰 검증 성공");

        // 6️⃣ 토큰에서 사용자 정보 추출
        Claims claims = jwtTokenProvider.getClaimsFromToken(token, !isRefreshRequest);
        if (claims == null) {
            log.error("🚨 JWT Claims 추출 실패. 토큰: {}", token);
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "유효한 사용자 정보가 없습니다.");
            return;
        }

        String username = claims.getSubject();
        Object roleObject = claims.get("auth"); // "auth" 키 확인

        // 🚨 role이 List로 저장된 경우 확인
        String role = (roleObject instanceof String) ? (String) roleObject : null;

        log.debug("🔹 JWT에서 추출된 사용자 정보 - username: {}, role: {}", username, role);

        // 7️⃣ 사용자 정보 가져오기
        Optional<User> optionalUser = userRepository.findByUsername(username);

        if (optionalUser.isEmpty()) {
            log.error("🚨 사용자 정보를 찾을 수 없음. JWT Subject: {}", username);
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "사용자 정보를 찾을 수 없습니다.");
            return;
        }

        User user = optionalUser.get();

        // 8️⃣ 관리자 API 요청 시 Role 검사
        if (!isRefreshRequest && !url.startsWith("/admin") && (role == null || !role.equals(Role.ADMIN.name()))) {
            log.warn("🚨 관리자 권한 없음. 요청 URL: {}, Role: {}", url, role);
            response.sendError(HttpServletResponse.SC_FORBIDDEN, "관리자 권한이 필요합니다.");
            return;
        }

        // 9️⃣ UserDetailsImpl 객체 생성
        UserDetailsImpl userDetails = new UserDetailsImpl(user);

        // 🔟 SecurityContext에 인증 정보 설정
        UsernamePasswordAuthenticationToken authentication =
                new UsernamePasswordAuthenticationToken(userDetails, null,
                        Collections.singletonList(new SimpleGrantedAuthority(role)));

        SecurityContextHolder.getContext().setAuthentication(authentication);
        log.info("✅ SecurityContext에 사용자 정보 저장 - username: {}, role: {}", username, role);

        // 🔄 필터 체인을 계속 진행
        filterChain.doFilter(request, response);
    }

    // 인증 없이 접근 가능한 URL
    private boolean isPublicUrl(String url) {
        return url.equals(LOGIN_URL) || url.equals(SIGNUP_URL) || url.equals(ADMIN_SIGNUP_URL);
    }

    // Refresh Token이 사용되는 URL인지 확인
    private boolean isRefreshTokenUrl(String url) {
        return url.equals(REFRESH_TOKEN_URL);
    }
}