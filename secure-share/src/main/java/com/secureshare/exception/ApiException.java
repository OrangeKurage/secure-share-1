package com.secureshare.exception;

import org.springframework.http.HttpStatus;

/** An error that maps directly to an HTTP status and a client-safe message. */
public class ApiException extends RuntimeException {
    private final HttpStatus status;

    public ApiException(HttpStatus status, String message) {
        super(message);
        this.status = status;
    }

    public HttpStatus getStatus() { return status; }

    public static ApiException badRequest(String m)   { return new ApiException(HttpStatus.BAD_REQUEST, m); }
    public static ApiException unauthorized(String m) { return new ApiException(HttpStatus.UNAUTHORIZED, m); }
    public static ApiException forbidden(String m)    { return new ApiException(HttpStatus.FORBIDDEN, m); }
    public static ApiException notFound(String m)     { return new ApiException(HttpStatus.NOT_FOUND, m); }
    public static ApiException conflict(String m)     { return new ApiException(HttpStatus.CONFLICT, m); }
    public static ApiException unprocessable(String m){ return new ApiException(HttpStatus.UNPROCESSABLE_ENTITY, m); }
}
