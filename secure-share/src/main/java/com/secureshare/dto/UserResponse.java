package com.secureshare.dto;

import com.secureshare.model.User;

/** Public view of a user. Never contains the password hash. */
public record UserResponse(Long userId, String fullName, String email, String publicKey) {
    public static UserResponse from(User u) {
        return new UserResponse(u.getUserId(), u.getFullName(), u.getEmail(), u.getPublicKey());
    }
}
