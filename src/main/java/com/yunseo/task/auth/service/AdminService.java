package com.yunseo.task.auth.service;

import com.yunseo.task.auth.entity.Role;
import com.yunseo.task.auth.entity.User;
import com.yunseo.task.auth.repository.UserRepository;
import org.springframework.stereotype.Service;

@Service
public class AdminService {

    private final UserRepository userRepository;

    public AdminService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    // 유저에게 관리자 권한을 부여하는 메소드
    public User grantAdminRoleToUser(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("사용자를 찾을 수 없습니다."));

        // 이미 관리자 권한을 가진 유저에게 권한을 부여할 수 없음
        if (user.getRole() == Role.ADMIN) {
            throw new RuntimeException("이미 관리자 권한이 부여된 사용자입니다.");
        }

        // 관리자 권한 부여
        user.setRole(Role.ADMIN);
        return userRepository.save(user); // 권한 부여된 유저 반환
    }
}