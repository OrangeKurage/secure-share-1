package com.secureshare.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

/** wrappedKey = the file's AES session key, RSA-OAEP-wrapped by the OWNER'S CLIENT for this recipient. */
public record ShareRecipient(@NotBlank @Email String email, @NotBlank String wrappedKey) {}
