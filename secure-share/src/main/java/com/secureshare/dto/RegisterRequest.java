package com.secureshare.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/** The client generates its own RSA key pair and sends only the PUBLIC key. */
public record RegisterRequest(
        @NotBlank @Size(max = 100) String fullName,
        @NotBlank @Email @Size(max = 100) String email,
        @NotBlank @Size(min = 8, max = 128) String password,
        @NotBlank String publicKey) {}
