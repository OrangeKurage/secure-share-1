package com.secureshare.dto;

import jakarta.validation.constraints.NotBlank;

public record RevokeRequest(@NotBlank String email) {}
