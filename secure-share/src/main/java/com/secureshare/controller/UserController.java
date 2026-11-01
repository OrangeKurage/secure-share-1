package com.secureshare.controller;

import com.secureshare.dto.LoginRequest;
import com.secureshare.dto.LoginResponse;
import com.secureshare.dto.RegisterRequest;
import com.secureshare.dto.UserResponse;
import com.secureshare.security.AuthenticatedUser;
import com.secureshare.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/users")
public class UserController {

    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @PostMapping("/register")
    public ResponseEntity<UserResponse> register(@Valid @RequestBody RegisterRequest req, HttpServletRequest http) {
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(UserResponse.from(userService.register(req, http.getRemoteAddr())));
    }

    @PostMapping("/login")
    public LoginResponse login(@Valid @RequestBody LoginRequest req, HttpServletRequest http) {
        return userService.login(req, http.getRemoteAddr());
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@AuthenticationPrincipal AuthenticatedUser user, HttpServletRequest http) {
        userService.logout(user, http.getRemoteAddr());
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/me")
    public UserResponse me(@AuthenticationPrincipal AuthenticatedUser user) {
        return UserResponse.from(userService.getById(user.userId()));
    }

    /** Public-key directory (SRS REST API). Requires login so strangers can't harvest the user list. */
    @GetMapping("/{id}/public-key")
    public UserResponse publicKey(@PathVariable("id") Long id) {
        return UserResponse.from(userService.getById(id));
    }

    /** Lets a sender pick a recipient by email instead of pasting keys (SRS 6.1 usability). */
    @GetMapping("/lookup")
    public UserResponse lookup(@RequestParam("email") String email) {
        return UserResponse.from(userService.getByEmail(email));
    }
}
