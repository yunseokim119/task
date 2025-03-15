package com.yunseo.task.auth.impl;

import com.yunseo.task.auth.entity.Role;
import com.yunseo.task.auth.entity.User;
import lombok.Getter;
import lombok.ToString;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collections;
import java.util.Collection;

@Slf4j
@Getter
@ToString
public class UserDetailsImpl implements UserDetails {

    private final Long id;
    private final String username;
    private final String password;
    private final Role role;

    public UserDetailsImpl(User user) {
        this.id = user.getId();
        this.username = user.getUsername();
        this.password = user.getPassword();
        this.role = user.getRole();

        log.info("🔍 UserDetailsImpl 생성됨 - ID: {}, Username: {}, Role: {}", id, username, role);
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        if (role == null) {
            log.warn("🚨 사용자 {}의 Role이 null입니다! 권한을 부여하지 않습니다.", username);
            return Collections.emptyList();
        }

        String authority = "ROLE_" + role.name();
        log.info("🔍 UserDetailsImpl - 반환되는 권한: {}", authority);
        return Collections.singletonList(new SimpleGrantedAuthority(authority));
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}