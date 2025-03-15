package com.yunseo.task.auth.controller;

import com.yunseo.task.auth.entity.Role;
import com.yunseo.task.auth.entity.User;
import com.yunseo.task.auth.security.JwtTokenProvider;
import com.yunseo.task.auth.service.AdminService;
import io.jsonwebtoken.Claims;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Collections;
import java.util.Map;

@RestController
@RequestMapping("/admin")
public class AdminController {

    private final AdminService adminService;
    private final JwtTokenProvider jwtTokenProvider; // JWT 토큰 검증을 위한 의존성 주입
    private static final Logger logger = LoggerFactory.getLogger(AdminController.class);

    public AdminController(AdminService adminService, JwtTokenProvider jwtTokenProvider) {
        this.adminService = adminService;
        this.jwtTokenProvider = jwtTokenProvider;
    }

    /**
     * 사용자에게 관리자 권한을 부여하는 API
     */
    @PatchMapping("/users/{userId}/roles")
    public ResponseEntity<Object> grantAdminRole(@PathVariable Long userId,
                                                 @RequestHeader(value = "Authorization", required = false) String token) {
        logger.debug("Received request to grant admin role to userId: {}", userId);

        // 1️⃣ [토큰 검증] 토큰이 존재하지 않거나 Bearer 형식이 아닐 경우
        if (token == null || !token.startsWith("Bearer ")) {
            logger.warn("Invalid or missing token: {}", token);
            return ResponseEntity.status(403).body(Map.of(
                    "error", Map.of(
                            "code", "ACCESS_DENIED",
                            "message", "유효한 토큰이 필요합니다."
                    )
            ));
        }

        String jwtToken = token.substring(7).trim(); // "Bearer " 제거

        // 2️⃣ [토큰 검증] Access Token만 유효성 검사
        if (!jwtTokenProvider.validateToken(jwtToken, true)) {
            logger.warn("Token validation failed. Token: {}", jwtToken);
            return ResponseEntity.status(403).body(Map.of(
                    "error", Map.of(
                            "code", "ACCESS_DENIED",
                            "message", "잘못된 토큰이거나 만료된 토큰입니다."
                    )
            ));
        }

        // 3️⃣ [관리자 권한 확인] 토큰에서 role 추출 후 ADMIN인지 확인
        Claims claims = jwtTokenProvider.getClaimsFromToken(jwtToken, true);
        String role = claims.get("role", String.class);

        if (!Role.ADMIN.name().equals(role)) {
            logger.warn("User is not an admin. userId: {}, Role: {}", userId, role);
            return ResponseEntity.status(403).body(Map.of(
                    "error", Map.of(
                            "code", "ACCESS_DENIED",
                            "message", "관리자 권한이 필요한 요청입니다. 접근 권한이 없습니다."
                    )
            ));
        }

        try {
            // 4️⃣ [권한 부여] 관리자가 아닌 유저에게 권한 부여
            User updatedUser = adminService.grantAdminRoleToUser(userId);
            logger.info("Successfully granted admin role to userId: {}", userId);

            return ResponseEntity.ok(Map.of(
                    "username", updatedUser.getUsername(),
                    "nickname", updatedUser.getNickname(),
                    "roles", Collections.singletonList(Map.of("role", "Admin"))
            ));
        } catch (RuntimeException e) {
            // 5️⃣ [예외 처리] 이미 관리자 권한이 있는 경우
            if ("이미 관리자 권한이 부여된 사용자입니다.".equals(e.getMessage())) {
                logger.warn("Attempted to grant admin role to a user who is already an admin. userId: {}", userId);
                return ResponseEntity.status(400).body(Map.of(
                        "error", Map.of(
                                "code", "ALREADY_ADMIN",
                                "message", "이미 관리자 권한이 부여된 사용자입니다."
                        )
                ));
            }

            // 6️⃣ [예외 처리] 기타 내부 오류 발생
            logger.error("Unexpected error while granting admin role to userId: {}", userId, e);
            return ResponseEntity.status(500).body(Map.of(
                    "error", Map.of(
                            "code", "INTERNAL_ERROR",
                            "message", "알 수 없는 오류가 발생했습니다."
                    )
            ));
        }
    }
}