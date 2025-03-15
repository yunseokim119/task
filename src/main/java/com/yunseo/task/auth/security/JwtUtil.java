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

    @Value("${jwt.secret.refresh.key}")
    private String secretRefreshKey;
    private Key refreshKey;

    @Value("${jwt.access.expiration}")
    private long accessTokenExpiration;

    @Value("${jwt.refresh.expiration}")
    private long refreshTokenExpiration;

    private final SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;

    private static final Logger logger = LoggerFactory.getLogger(JwtUtil.class);

    @PostConstruct
    public void init() {
        try {
            accessKey = Keys.hmacShaKeyFor(Base64.getDecoder().decode(secretAccessKey));
            refreshKey = Keys.hmacShaKeyFor(Base64.getDecoder().decode(secretRefreshKey));
            logger.info("✅ JWT Secret Keys 초기화 완료");
        } catch (IllegalArgumentException e) {
            logger.error("🚨 JWT SecretKey 초기화 실패: {}", e.getMessage());
            throw new RuntimeException("JWT SecretKey 초기화 실패", e);
        }
    }

    /**
     * ✅ JWT 토큰 생성 (username + role)
     */
    public String generateToken(String username, String role) {
        Date now = new Date();

        // 역할이 null이면 기본값 "ROLE_USER" 설정
        String roleWithPrefix = (role != null && !role.isEmpty()) ? "ROLE_" + role.toUpperCase() : "ROLE_USER";

        logger.info("🔹 JWT 생성 - username: {}, role: {}", username, roleWithPrefix);

        return BEARER_PREFIX +
                Jwts.builder()
                        .setSubject(username)
                        .claim(AUTHORIZATION_KEY, roleWithPrefix)  // "auth" 클레임에 ROLE_ 접두어를 추가한 역할 저장
                        .setExpiration(new Date(now.getTime() + accessTokenExpiration))
                        .setIssuedAt(now)
                        .signWith(accessKey, signatureAlgorithm)
                        .compact();
    }

    /**
     * ✅ JWT 토큰 검증 (Bearer 제거 후 실행)
     */
    public boolean validateToken(String token, String type) {
        try {
            String cleanToken = substringToken(token);
            if (cleanToken == null) {
                logger.warn("🚨 토큰 검증 실패 - Bearer 제거 후 토큰이 null입니다.");
                return false;
            }

            Key key = ACCESS.equals(type) ? accessKey : refreshKey;
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(cleanToken);

            logger.info("✅ JWT 검증 성공");
            return true;
        } catch (SecurityException | MalformedJwtException e) {
            logger.error("🚨 잘못된 JWT 서명입니다: {}", e.getMessage());
        } catch (ExpiredJwtException e) {
            logger.error("🚨 만료된 JWT 토큰입니다.");
        } catch (UnsupportedJwtException e) {
            logger.error("🚨 지원되지 않는 JWT 토큰입니다.");
        } catch (IllegalArgumentException e) {
            logger.error("🚨 JWT 토큰이 잘못되었습니다.");
        }
        return false;
    }

    /**
     * ✅ Bearer 제거 후 JWT 토큰 반환
     */
    public String substringToken(String tokenValue) {
        if (StringUtils.hasText(tokenValue) && tokenValue.startsWith(BEARER_PREFIX)) {
            return tokenValue.substring(BEARER_PREFIX.length()).trim();
        }
        logger.warn("🚨 Authorization 헤더가 존재하지 않거나 잘못된 형식입니다.");
        return null;
    }

    /**
     * ✅ JWT 토큰에서 사용자 정보(Claims) 가져오기
     */
    public Claims getUserInfoFromToken(String token, String type) {
        try {
            String cleanToken = substringToken(token);
            if (cleanToken == null) {
                logger.warn("🚨 JWT에서 사용자 정보 추출 실패 - Bearer 제거 후 토큰이 null");
                return null;
            }

            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(getSecretKey(type))
                    .build()
                    .parseClaimsJws(cleanToken)
                    .getBody();

            // 🚨 Role이 null인지 체크하고, 정확한 타입 변환 수행
            Object rawRole = claims.get(AUTHORIZATION_KEY);
            String extractedRole;

            if (rawRole instanceof String) {
                extractedRole = (String) rawRole;
            } else if (rawRole != null) {
                extractedRole = rawRole.toString();
            } else {
                extractedRole = "ROLE_UNKNOWN";
            }

            logger.info("✅ JWT Claims 추출 완료 - username: {}, role: {}", claims.getSubject(), extractedRole);
            return claims;
        } catch (Exception e) {
            logger.error("🚨 JWT Claims 추출 실패: {}", e.getMessage());
            return null;
        }
    }

    /**
     * ✅ AccessToken 또는 RefreshToken의 서명 키 가져오기
     */
    private Key getSecretKey(String type) {
        return type.equals(ACCESS) ? accessKey : refreshKey;
    }
}