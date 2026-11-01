package com.secureshare.security;

/** The principal placed in the SecurityContext after a JWT has been validated. */
public record AuthenticatedUser(Long userId, String email, Long sessionId) {}
