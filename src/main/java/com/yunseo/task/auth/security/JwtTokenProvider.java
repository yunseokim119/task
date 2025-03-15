package com.yunseo.task.auth.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import java.util.Date;

@Component
public class JwtTokenProvider {

    private static final Logger logger = LoggerFactory.getLogger(JwtTokenProvider.class);

    @Value("${jwt.secret.access.key}")
    private String jwtAccessSecret;

    @Value("${jwt.secret.refresh.key}")
    private String jwtRefreshSecret;

    @Value("${jwt.access.expiration}")
    private long accessExpiration;

    @Value("${jwt.refresh.expiration}")
    private long refreshExpiration;

    private SecretKey accessKey;
    private SecretKey refreshKey;

    /**
     * ✅ JWT Secret Key 초기화
     */
    @PostConstruct
    public void init() {
        try {
            accessKey = createSecretKey(jwtAccessSecret);
            refreshKey = createSecretKey(jwtRefreshSecret);

            logger.info("✅ JWT Secret Keys 초기화 완료");
            logger.debug("🔹 Access Key: {}", Base64.getEncoder().encodeToString(accessKey.getEncoded()));
            logger.debug("🔹 Refresh Key: {}", Base64.getEncoder().encodeToString(refreshKey.getEncoded()));
        } catch (Exception e) {
            logger.error("❌ JWT SecretKey 초기화 실패: {}", e.getMessage());
            throw new RuntimeException("JWT SecretKey 초기화 실패", e);
        }
    }

    private SecretKey createSecretKey(String secret) {
        try {
            byte[] decodedKey = Base64.getDecoder().decode(secret.strip());
            return new SecretKeySpec(decodedKey, SignatureAlgorithm.HS256.getJcaName());
        } catch (IllegalArgumentException e) {
            throw new RuntimeException("❌ Invalid Base64 SECRET_KEY: " + e.getMessage());
        }
    }

    /**
     * ✅ Access Token 생성
     */
    public String createAccessToken(String username, String role) {
        return createToken(username, role, true);
    }

    /**
     * ✅ Refresh Token 생성
     */
    public String createRefreshToken(String username) {
        return createToken(username, null, false);
    }

    /**
     * ✅ JWT 토큰 생성 (Access / Refresh 구분)
     */
    private String createToken(String username, String role, boolean isAccessToken) {
        Claims claims = Jwts.claims().setSubject(username);
        if (isAccessToken) {
            logger.debug("🔍 AccessToken 생성 - username: {}, role: {}", username, role);
            if (role != null) {
                claims.put("role", role);
            } else {
                logger.warn("🚨 AccessToken 생성 중 role 값이 null입니다.");
            }
        }

        Date now = new Date();
        long expirationTime = isAccessToken ? accessExpiration : refreshExpiration;
        Date expiryDate = new Date(now.getTime() + expirationTime);

        String token = Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(now)
                .setExpiration(expiryDate)
                .signWith(getSigningKey(isAccessToken))
                .compact();

        logger.debug("✅ 생성된 JWT: {}", token);
        return token;
    }

    /**
     * ✅ JWT 토큰 검증
     */
    public boolean validateToken(String token, boolean isAccessToken) {
        try {
            Jwts.parserBuilder()
                    .setSigningKey(getSigningKey(isAccessToken))
                    .build()
                    .parseClaimsJws(token);
            logger.debug("✅ JWT 검증 성공: {}", token);
            return true;
        } catch (io.jsonwebtoken.io.DecodingException e) {
            logger.error("🚨 JWT Base64 디코딩 실패: {} | 원인: {}", token, e.getMessage());
        } catch (io.jsonwebtoken.security.SignatureException e) {
            logger.error("🚨 JWT 서명 검증 실패: {} | 원인: {}", token, e.getMessage());
        } catch (Exception e) {
            logger.error("❌ JWT 검증 실패: {} | 원인: {}", token, e.getMessage());
        }
        return false;
    }

    /**
     * ✅ JWT 토큰에서 사용자 정보(Claims) 추출
     */
    public Claims getClaimsFromToken(String token, boolean isAccessToken) {
        return Jwts.parserBuilder()
                .setSigningKey(getSigningKey(isAccessToken))
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    /**
     * ✅ Authorization 헤더에서 Bearer 토큰을 추출
     */
    public String resolveToken(String bearerToken) {
        if (bearerToken == null) {
            logger.warn("🚨 Authorization 헤더가 존재하지 않습니다.");
            return null;
        }

        if (!bearerToken.startsWith("Bearer ")) {
            logger.warn("🚨 Authorization 헤더가 'Bearer '로 시작하지 않습니다: {}", bearerToken);
            return null;
        }

        // 🔥 공백 및 개행 문자 제거
        String token = bearerToken.substring(7).replaceAll("\\s+", "");

        if (token.isEmpty()) {
            logger.warn("🚨 추출된 JWT 토큰이 비어 있습니다.");
            return null;
        }

        logger.debug("✅ 추출된 JWT 토큰: {}", token);
        return token;
    }

    /**
     * ✅ AccessToken 또는 RefreshToken의 서명 키 가져오기
     */
    private SecretKey getSigningKey(boolean isAccessToken) {
        if (isAccessToken) {
            if (accessKey == null) {
                throw new IllegalStateException("Access SecretKey가 초기화되지 않았습니다.");
            }
            return accessKey;
        } else {
            if (refreshKey == null) {
                throw new IllegalStateException("Refresh SecretKey가 초기화되지 않았습니다.");
            }
            return refreshKey;
        }
    }
}