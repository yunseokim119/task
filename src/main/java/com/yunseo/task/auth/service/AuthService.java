package com.yunseo.task.auth.service;

import com.yunseo.task.auth.dto.LoginRequestDto;
import com.yunseo.task.auth.dto.SignupRequestDto;
import com.yunseo.task.auth.entity.Role;
import com.yunseo.task.auth.entity.User;
import com.yunseo.task.auth.exception.CustomException;
import com.yunseo.task.auth.exception.ErrorCode;
import com.yunseo.task.auth.exception.UserAlreadyExistsException;
import com.yunseo.task.auth.exception.UserNotFoundException;
import com.yunseo.task.auth.repository.UserRepository;
import com.yunseo.task.auth.security.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;

    // 회원가입
    @Transactional
    public void signup(SignupRequestDto signupRequestDto) {
        if (userRepository.existsByUsername(signupRequestDto.getUsername())) {
            throw new UserAlreadyExistsException();
        }

        String encodedPassword = passwordEncoder.encode(signupRequestDto.getPassword());

        User user = User.builder()
                .username(signupRequestDto.getUsername())
                .password(encodedPassword)
                .role(Role.USER) // 기본 USER 권한
                .nickname(signupRequestDto.getNickname())
                .build();

        userRepository.save(user);
    }

    // 관리자 회원가입
    @Transactional
    public void adminSignup(SignupRequestDto signupRequestDto) {
        if (userRepository.existsByUsername(signupRequestDto.getUsername())) {
            throw new UserAlreadyExistsException();
        }

        String encodedPassword = passwordEncoder.encode(signupRequestDto.getPassword());

        User user = User.builder()
                .username(signupRequestDto.getUsername())
                .password(encodedPassword)
                .role(Role.ADMIN)
                .nickname(signupRequestDto.getNickname())
                .build();

        userRepository.save(user);
    }

    // 로그인 (JWT 발급)
    public String login(LoginRequestDto loginRequestDto) {
        User user = userRepository.findByUsername(loginRequestDto.getUsername())
                .orElseThrow(UserNotFoundException::new);

        if (!passwordEncoder.matches(loginRequestDto.getPassword(), user.getPassword())) {
            throw new CustomException(ErrorCode.INVALID_ROLE);
        }

        return jwtUtil.generateToken(user.getUsername(), user.getRole().name());
    }
}