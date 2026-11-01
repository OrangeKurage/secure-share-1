package com.secureshare.dto;

import java.time.Instant;

public record LoginResponse(String token, String tokenType, Instant expiresAt, Long userId, String fullName) {}
