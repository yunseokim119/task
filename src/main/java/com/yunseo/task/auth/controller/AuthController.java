package com.yunseo.task.auth.controller;

import com.yunseo.task.auth.dto.LoginRequestDto;
import com.yunseo.task.auth.dto.SignupRequestDto;
import com.yunseo.task.auth.entity.AuthUser;
import com.yunseo.task.auth.entity.User;
import com.yunseo.task.auth.service.AuthService;
import com.yunseo.task.auth.exception.UserAlreadyExistsException;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    // 회원가입
    @PostMapping("/signup")
    public ResponseEntity<?> signup(@Valid @RequestBody SignupRequestDto signupRequestDto) {
        try {
            authService.signup(signupRequestDto);
            // 회원가입 성공 시 반환 형식
            return ResponseEntity.ok().body(
                    Map.of(
                            "username", signupRequestDto.getUsername(),
                            "nickname", signupRequestDto.getNickname(),
                            "roles", List.of(Map.of("role", "USER"))
                    )
            );
        } catch (UserAlreadyExistsException e) {
            // 이미 존재하는 사용자일 경우 반환 형식
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(
                    Map.of(
                            "error", Map.of(
                                    "code", "USER_ALREADY_EXISTS",
                                    "message", e.getMessage()
                            )
                    )
            );
        }
    }

    // 관리자 회원가입
    @PreAuthorize("hasRole('ADMIN')")
    @PostMapping("/admin/signup")
    public ResponseEntity<?> adminSignup(@Valid @RequestBody SignupRequestDto signupRequestDto) {
        try {
            // 관리자로 회원가입
            authService.adminSignup(signupRequestDto);
            return ResponseEntity.ok().body(
                    Map.of(
                            "username", signupRequestDto.getUsername(),
                            "nickname", signupRequestDto.getNickname(),
                            "roles", List.of(Map.of("role", "ADMIN"))
                    )
            );
        } catch (UserAlreadyExistsException e) {
            // 이미 존재하는 사용자일 경우 반환 형식
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(
                    Map.of(
                            "error", Map.of(
                                    "code", "USER_ALREADY_EXISTS",
                                    "message", e.getMessage()
                            )
                    )
            );
        }
    }

    // 로그인
    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequestDto loginRequestDto) {
        try {
            String token = authService.login(loginRequestDto);
            // 로그인 성공 시 반환 형식
            return ResponseEntity.ok().body(
                    Map.of(
                            "token", token
                    )
            );
        } catch (Exception e) {
            // 로그인 실패 시 반환 형식
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(
                    Map.of(
                            "error", Map.of(
                                    "code", "INVALID_CREDENTIALS",
                                    "message", e.getMessage()
                            )
                    )
            );
        }
    }

    // 관리자 권한 부여 API
    @PatchMapping("/admin/users/{userId}/roles")
    public ResponseEntity<?> assignAdminRole(@PathVariable Long userId) {
        // 현재 인증된 사용자 확인
        AuthUser currentUser = (AuthUser) SecurityContextHolder.getContext().getAuthentication().getPrincipal();

        // 현재 사용자가 관리자 권한을 가지고 있는지 확인
        if (!currentUser.getRole().equals("ADMIN")) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(
                    Map.of(
                            "error", Map.of(
                                    "code", "ACCESS_DENIED",
                                    "message", "관리자 권한이 필요한 요청입니다. 접근 권한이 없습니다."
                            )
                    )
            );
        }

        try {
            // 사용자에게 관리자 권한 부여
            User updatedUser = authService.assignRoleToUser(userId, "ADMIN");

            // 관리자 권한 부여 성공 응답
            return ResponseEntity.ok().body(
                    Map.of(
                            "username", updatedUser.getUsername(),
                            "nickname", updatedUser.getNickname(),
                            "roles", List.of(Map.of("role", "Admin"))
                    )
            );
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(
                    Map.of(
                            "error", Map.of(
                                    "code", "USER_NOT_FOUND",
                                    "message", "사용자를 찾을 수 없습니다."
                            )
                    )
            );
        }
    }
}