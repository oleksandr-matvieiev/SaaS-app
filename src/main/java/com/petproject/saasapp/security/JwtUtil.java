package com.petproject.saasapp.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SecurityException;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.stream.Collectors;

@Component
public class JwtUtil {

    @Value("${jwt.secret}")
    private String secret;

    @Value("${jwt.expiration}")
    private Long expiration;

    private SecretKey key;

    @PostConstruct
    public void init() {
        this.key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    }

    public String generateToken(String email, List<String> roles) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("roles", roles);

        return Jwts.builder()
                .subject(email)
                .claims(claims)
                .issuedAt(new Date())
                .expiration(new Date((new Date()).getTime() + expiration))
                .signWith(key)
                .compact();
    }

    public String getEmailFromToken(String token) {
        Claims claims = Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token)
                .getPayload();

        return claims.getSubject();
    }

    public List<String> getRolesFromToken(String token) {
        Claims claims = Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token)
                .getPayload();

        Object rolesObject = claims.get("roles");

        if (rolesObject instanceof List<?>) {
            return ((List<?>) rolesObject).stream()
                    .map(Object::toString)
                    .collect(Collectors.toList());
        }

        return Collections.emptyList();
    }

    public boolean validateToken(String token) {
        try {
            Jwts.parser().verifyWith(key).build().parse(token);
            return true;
        } catch (SecurityException | MalformedJwtException e){
            throw new AuthenticationCredentialsNotFoundException("JWT was expired or incorrect.");
        } catch (ExpiredJwtException e){
            throw new AuthenticationCredentialsNotFoundException("Expired JWT token.");
        } catch (IllegalArgumentException e){
            throw new AuthenticationCredentialsNotFoundException("JWT is invalid.");
        } catch (UnsupportedJwtException e){
            throw new AuthenticationCredentialsNotFoundException("Unsupported JWT token.");
        }
    }
}
