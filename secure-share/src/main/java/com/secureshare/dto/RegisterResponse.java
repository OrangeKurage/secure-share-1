package com.secureshare.dto;

public record RegisterResponse(Long userId, String fullName, String email, String publicKey,
                               String privateKey, String warning) {}
