package com.yunseo.task.auth.security;

import com.yunseo.task.auth.entity.User;
import com.yunseo.task.auth.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

    @Autowired
    private UserRepository userRepository;  // UserRepository 주입

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // HttpSecurity를 사용한 보안 설정
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.csrf().disable()
                .authorizeRequests()
                .requestMatchers("/api/auth/signup", "/api/auth/admin/signup", "/api/auth/login").permitAll()
                .anyRequest().authenticated();  // 나머지 요청은 인증 필요

        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        return username -> {
            // DB에서 사용자 조회
            User user = userRepository.findByUsername(username)
                    .orElseThrow(() -> new UsernameNotFoundException("사용자가 존재하지 않습니다."));

            return org.springframework.security.core.userdetails.User.builder()
                    .username(user.getUsername())
                    .password(user.getPassword())
                    .accountExpired(false)  // 계정 만료 여부
                    .credentialsExpired(false)  // 자격 증명 만료 여부
                    .disabled(false)  // 계정 비활성화 여부
                    .accountLocked(false)  // 계정 잠김 여부
                    .build();
        };
    }
}