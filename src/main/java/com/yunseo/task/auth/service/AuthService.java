package com.yunseo.task.auth.service;

import com.yunseo.task.auth.dto.LoginRequestDto;
import com.yunseo.task.auth.dto.SignupRequestDto;
import com.yunseo.task.auth.entity.Role;
import com.yunseo.task.auth.entity.User;
import com.yunseo.task.auth.repository.UserRepository;
import com.yunseo.task.auth.security.JwtUtil;
import com.yunseo.task.auth.exception.UserAlreadyExistsException;  // 예외 클래스 임포트
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;

    private static final Logger logger = LoggerFactory.getLogger(AuthService.class);

    // 회원가입
    @Transactional
    public void signup(SignupRequestDto signupRequestDto) {
        // 중복 사용자 체크
        if (userRepository.existsByUsername(signupRequestDto.getUsername())) {
            throw new UserAlreadyExistsException("이미 존재하는 사용자입니다.");  // 사용자 정의 예외 던지기
        }

        // 비밀번호 암호화
        String encodedPassword = passwordEncoder.encode(signupRequestDto.getPassword());

        // role은 기본적으로 USER로 설정
        Role role = Role.valueOf(signupRequestDto.getRole().toUpperCase());

        // 사용자 객체 생성
        User user = User.builder()
                .username(signupRequestDto.getUsername())
                .password(encodedPassword)
                .role(role)
                .nickname(signupRequestDto.getNickname())  // nickname 추가
                .build();

        // 사용자 저장
        userRepository.save(user);
    }

    // 관리자 회원가입
    public void adminSignup(SignupRequestDto signupRequestDto) {
        // 관리자 계정은 별도로 중복 체크가 되어야 할 수도 있지만, 기본적으로는 일반 회원가입과 동일
        if (userRepository.existsByUsername(signupRequestDto.getUsername())) {
            throw new UserAlreadyExistsException("이미 존재하는 사용자입니다.");
        }

        // 비밀번호 암호화
        String encodedPassword = passwordEncoder.encode(signupRequestDto.getPassword());

        // ROLE은 ADMIN으로 설정
        Role role = Role.valueOf("ADMIN");

        // 사용자 객체 생성 (관리자)
        User user = User.builder()
                .username(signupRequestDto.getUsername())
                .password(encodedPassword)
                .role(role)
                .nickname(signupRequestDto.getNickname())  // nickname 추가
                .build();

        // 사용자 저장
        userRepository.save(user);
    }

    // 로그인 (JWT 발급)
    public String login(LoginRequestDto loginRequestDto) {
        // 사용자 조회
        User user = userRepository.findByUsername(loginRequestDto.getUsername())
                .orElseThrow(() -> new IllegalArgumentException("존재하지 않는 사용자입니다."));

        // 비밀번호 확인
        if (!passwordEncoder.matches(loginRequestDto.getPassword(), user.getPassword())) {
            throw new IllegalArgumentException("아이디 또는 비밀번호가 올바르지 않습니다.");
        }

        // JWT 토큰 발급
        return jwtUtil.generateToken(user.getUsername(), user.getRole().name());
    }

    // 관리자 권한 부여
    public User assignRoleToUser(Long userId, String role) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("사용자를 찾을 수 없습니다."));

        // Role을 직접 설정 (ADMIN 역할 부여)
        user.setRole(Role.valueOf(role));

        // 업데이트된 사용자 저장
        return userRepository.save(user);
    }
}