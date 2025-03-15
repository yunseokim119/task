package com.yunseo.task.auth.service;

import com.yunseo.task.auth.entity.User;
import com.yunseo.task.auth.impl.UserDetailsImpl;
import com.yunseo.task.auth.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // 사용자 정보를 DB에서 조회
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("사용자가 존재하지 않습니다."));

        // UserDetailsImpl 객체를 반환
        return new UserDetailsImpl(user);
    }
}