package com.parth_collab.auth_service.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.parth_collab.auth_service.model.User;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;
import java.util.Map;

@Component
public class JwtUtils {

    @Value("${jwt.secret}")
    private String jwtSecret;

    @Value("${jwt.expirationMs}")
    private int jwtExpirationMs;

    private final ObjectMapper objectMapper;

    public JwtUtils(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    // Generate JWT dynamically from User object
    public String generateJwtToken(User user) {
        Map<String, Object> claims = objectMapper.convertValue(user, Map.class);

        claims.remove("password"); // Never include password
        claims.remove("id");
        Key key = Keys.hmacShaKeyFor(jwtSecret.getBytes());

        return Jwts.builder()
                .setClaims(claims)
                .setSubject(user.getUsername())
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + jwtExpirationMs))
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    // Extract username (subject) from JWT
    public String getUsernameFromJwt(String token) {
        return parseClaims(token).getBody().getSubject();
    }

    // Extract all claims from JWT
    public Claims getAllClaimsFromJwt(String token) {
        return parseClaims(token).getBody();
    }

    // Validate token
    public boolean validateJwtToken(String authToken) {
        try {
            parseClaims(authToken);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            // Invalid token
            return false;
        }
    }

    // Helper method to parse JWT using modern JJWT parser
    private Jws<Claims> parseClaims(String token) {
        Key key = Keys.hmacShaKeyFor(jwtSecret.getBytes());
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token);
    }
}
