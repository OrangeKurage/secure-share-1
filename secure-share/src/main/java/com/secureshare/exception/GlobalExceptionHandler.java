package com.secureshare.exception;

import com.secureshare.crypto.CryptoException;
import com.secureshare.crypto.IntegrityException;
import com.secureshare.crypto.SignatureVerificationException;
import com.secureshare.crypto.UnauthorizedRecipientException;
import java.time.Instant;
import java.util.stream.Collectors;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.multipart.MaxUploadSizeExceededException;

@RestControllerAdvice
public class GlobalExceptionHandler {

    private static ResponseEntity<ApiError> build(HttpStatus status, String message) {
        return ResponseEntity.status(status)
                .contentType(org.springframework.http.MediaType.APPLICATION_JSON)
                .body(new ApiError(status.value(), status.getReasonPhrase(), message, Instant.now()));
    }

    @ExceptionHandler(ApiException.class)
    public ResponseEntity<ApiError> handleApi(ApiException e) {
        return build(e.getStatus(), e.getMessage());
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiError> handleValidation(MethodArgumentNotValidException e) {
        String msg = e.getBindingResult().getFieldErrors().stream()
                .map(f -> f.getField() + ": " + f.getDefaultMessage())
                .collect(Collectors.joining("; "));
        return build(HttpStatus.BAD_REQUEST, msg);
    }

    @ExceptionHandler(MaxUploadSizeExceededException.class)
    public ResponseEntity<ApiError> handleTooBig(MaxUploadSizeExceededException e) {
        return build(HttpStatus.PAYLOAD_TOO_LARGE, "File is too large");
    }

    // ---- crypto failures -> distinct, meaningful status codes (fail closed) ----
    @ExceptionHandler(UnauthorizedRecipientException.class)
    public ResponseEntity<ApiError> handleUnauthorizedRecipient(UnauthorizedRecipientException e) {
        return build(HttpStatus.FORBIDDEN, e.getMessage());
    }

    @ExceptionHandler(IntegrityException.class)
    public ResponseEntity<ApiError> handleIntegrity(IntegrityException e) {
        return build(HttpStatus.UNPROCESSABLE_ENTITY, e.getMessage());
    }

    @ExceptionHandler(SignatureVerificationException.class)
    public ResponseEntity<ApiError> handleSignature(SignatureVerificationException e) {
        return build(HttpStatus.UNPROCESSABLE_ENTITY, e.getMessage());
    }

    @ExceptionHandler(CryptoException.class)
    public ResponseEntity<ApiError> handleCrypto(CryptoException e) {
        return build(HttpStatus.BAD_REQUEST, e.getMessage());
    }
}
