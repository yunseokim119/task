package com.yunseo.task.auth.dto;

import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
public class JwtResponseDto {
    private String accessToken;
    private String refreshToken;
}
