package com.yunseo.task.auth.controller;

import com.yunseo.task.auth.dto.LoginRequestDto;
import com.yunseo.task.auth.dto.SignupRequestDto;
import com.yunseo.task.auth.exception.UserAlreadyExistsException;
import com.yunseo.task.auth.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
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
}