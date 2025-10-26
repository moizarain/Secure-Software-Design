package edu.nu.owaspapivulnlab.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Base64;
import java.util.Date;
import java.util.Map;

@Service
public class JwtService {

    // --- FIX 7: JWT Hardening ---
    // Inject all properties from application.properties
    
    @Value("${jwt.secret}")
    private String secret;

    @Value("${jwt.expiration-ms}")
    private long expirationTime; // e.g., 3600000 (1 hour)

    @Value("${jwt.issuer}")
    private String issuer;

    @Value("${jwt.audience}")
    private String audience;

    private SecretKey getSigningKey() {
        // Decode the Base64 secret from properties into a secure key
        byte[] keyBytes = Base64.getDecoder().decode(secret);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    // Renamed from 'issue' to 'generateToken' for clarity
    public String generateToken(String subject, Map<String, Object> claims) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + expirationTime); // Set short TTL

        return Jwts.builder()
                .setClaims(claims)
                .setSubject(subject)
                .setIssuer(issuer)       // Add issuer claim
                .setAudience(audience)   // Add audience claim
                .setIssuedAt(now)
                .setExpiration(expiryDate) // Add expiration claim
                .signWith(getSigningKey(), SignatureAlgorithm.HS512) // Use a strong algorithm
                .compact();
    }

    // Renamed from 'issue' to a version without extra claims if needed
    public String issue(String subject, Map<String, Object> claims) {
        return generateToken(subject, claims);
    }


    // --- FIX 7: JWT Hardening (Strict Validation) ---
    
    public Claims validateAndParseToken(String token) {
        // This method will throw a JwtException if any claim is invalid
        return Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .requireIssuer(issuer)       // Validate issuer
                .requireAudience(audience)   // Validate audience
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
    
    // You might also need a simple boolean validator for the SecurityFilter
    public boolean validateToken(String token) {
        try {
            validateAndParseToken(token);
            return true;
        } catch (Exception e) {
            return false; // Token is invalid (expired, wrong signature, etc.)
        }
    }
}