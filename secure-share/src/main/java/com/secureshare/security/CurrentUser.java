package com.secureshare.security;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

public final class CurrentUser {
    private CurrentUser() {}

    /** Id of the authenticated user (set by JwtAuthFilter). Only call on protected routes. */
    public static Long id() {
        Authentication a = SecurityContextHolder.getContext().getAuthentication();
        return (Long) a.getPrincipal();
    }
}
