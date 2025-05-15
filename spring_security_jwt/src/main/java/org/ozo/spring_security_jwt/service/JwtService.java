package org.ozo.spring_security_jwt.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {
    @Value("${security.jwt.key}")
    private String jwtKey; // Key used to sign the JWT

    @Value("${security.jwt.expiration}")
    private Long jwtExpiration; // Expiration time for the JWT - 7 days

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    } // Extracts the username from the JWT

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    } // Extracts a specific claim from the JWT

    private Claims extractAllClaims(String token) {
        return Jwts
                .parser()
                .verifyWith(getSecretKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    } // Extracts all claims from the JWT

    private SecretKey getSecretKey() {
        byte[] keyBytes = Decoders.BASE64.decode(jwtKey);
        return Keys.hmacShaKeyFor(keyBytes);
    } // Generates a secret key from the base64-encoded key

    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    } // Checks if the token is valid

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    } // Checks if the token is expired

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    } // Extracts the expiration date from the JWT

    public String generateToken(String username) {
        return generateToken(new HashMap<>(), username);
    } // Generates a JWT with the given username

    public String generateToken(Map<String, Object> extraClaims, String username) {
        return Jwts.builder()
                .claims(extraClaims)
                .subject(username)
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + jwtExpiration))
                .signWith(getSecretKey(), SignatureAlgorithm.HS256)
                .compact();
    } // Generates a JWT with the given claims and username
}
