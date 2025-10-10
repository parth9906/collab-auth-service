package com.parth_collab.auth_service.controller;

import com.parth_collab.auth_service.dto.UserDTO;
import com.parth_collab.auth_service.model.User;
import com.parth_collab.auth_service.security.JwtUtils;
import com.parth_collab.auth_service.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final JwtUtils jwtUtils;

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody User user) {
        if (authService.findByUsername(user.getUsername()) != null) {
            return ResponseEntity.badRequest().body(Map.of("error", "Username already exists"));
        }
        User saved = authService.registerUser(user);
        return ResponseEntity.ok(saved);
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody User user) {
        User existing = authService.findByUsername(user.getUsername());
        if (existing == null) {
            return ResponseEntity.badRequest().body(Map.of("error", "User not found"));
        }
        if (!authService.validatePassword(user.getPassword(), existing.getPassword())) {
            return ResponseEntity.badRequest().body(Map.of("error", "Invalid password"));
        }
        String token = jwtUtils.generateJwtToken(existing);

        UserDTO userDTO = new UserDTO(existing);
        return ResponseEntity.ok(Map.of("token", token, "user", userDTO));
    }
}
