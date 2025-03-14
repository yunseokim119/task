package com.yunseo.task.auth.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.security.Key;
import java.util.Base64;
import java.util.Date;

@Component
public class JwtUtil {
    public static final String ACCESS = "ACCESS";
    public static final String REFRESH = "REFRESH";

    public static final String AUTHORIZATION_KEY = "auth";
    public static final String BEARER_PREFIX = "Bearer ";

    @Value("${jwt.secret.access.key}")
    private String secretAccessKey;
    private Key accessKey;

    private final long TOKEN_ACCESS_TIME = 60 * 60 * 24 * 1000L;

    @Value("${jwt.secret.refresh.key}")
    private String secretRefreshKey;
    private Key refreshKey;

    private final long TOKEN_REFRESH_TIME = 60 * 60 * 24 * 1000L;

    private final SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;

    // 로그 설정
    public static final Logger logger = LoggerFactory.getLogger("JWT 관련 로그");

    @PostConstruct
    public void init() {
        accessKey = Keys.hmacShaKeyFor(Base64.getDecoder().decode(secretAccessKey));
        refreshKey = Keys.hmacShaKeyFor(Base64.getDecoder().decode(secretRefreshKey));
    }

    // JWT 토큰 생성 (username + role 기반)
    public String generateToken(String username, String role) {
        Date date = new Date();
        return BEARER_PREFIX +
                Jwts.builder()
                        .setSubject(username)
                        .claim("user_role", role) // 역할을 "user_role"로 변경
                        .setExpiration(new Date(date.getTime() + TOKEN_ACCESS_TIME))
                        .setIssuedAt(date)
                        .signWith(accessKey, signatureAlgorithm)
                        .compact();
    }

    // 토큰 검증
    public boolean validateToken(String token, String type) {
        try {
            Key key = type.equals(ACCESS) ? accessKey : refreshKey;
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
            return true;
        } catch (SecurityException | MalformedJwtException e) {
            logger.error("잘못된 JWT 서명입니다. Token: {}", token, e);
        } catch (ExpiredJwtException e) {
            logger.error("만료된 JWT 토큰입니다. Token: {}", token, e);
        } catch (UnsupportedJwtException e) {
            logger.error("지원되지 않는 JWT 토큰입니다. Token: {}", token, e);
        } catch (IllegalArgumentException e) {
            logger.error("JWT 토큰이 잘못되었습니다. Token: {}", token, e);
        }
        return false;
    }

    // JWT 토큰 substring
    public String substringToken(String tokenValue) {
        if (StringUtils.hasText(tokenValue) && tokenValue.startsWith(BEARER_PREFIX)) {
            return tokenValue.substring(BEARER_PREFIX.length());
        }
        logger.error("Not Found Token");
        return null;  // 또는 Optional.empty() 반환 가능
    }

    // 토큰에서 사용자 정보 가져오기
    public Claims getUserInfoFromToken(String token , String type) {
        Key key = type.equals(ACCESS) ? accessKey : refreshKey;
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
}