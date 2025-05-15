package org.ozo.spring_security_jwt.service;

import lombok.RequiredArgsConstructor;
import org.ozo.spring_security_jwt.dto.AuthenticationRequest;
import org.ozo.spring_security_jwt.dto.AuthenticationResponse;
import org.ozo.spring_security_jwt.dto.UserCreateRequest;
import org.ozo.spring_security_jwt.dto.UserResponseDto;
import org.ozo.spring_security_jwt.entity.User;
import org.ozo.spring_security_jwt.repository.UserRepository;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

/**
 * Service class for handling authentication and user registration.
 */

@Service
@RequiredArgsConstructor
public class AuthenticationService {
    private final JwtService jwtService; // Service to handle JWT operations
    private final AuthenticationManager authenticationManager; // Authentication manager to handle authentication
    private final UserRepository userRepository; // Repository to interact with the database
    private final PasswordEncoder passwordEncoder; // Password encoder to encode passwords

    public AuthenticationResponse register(UserCreateRequest request) {
        userRepository.save(new User(null, request.getUsername(), passwordEncoder.encode(request.getPassword()))); // Save the new user
        String token = jwtService.generateToken(request.getUsername());
        return new AuthenticationResponse(token);
    } // Method to register a new user

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword())); // Authenticate the user
        var user = userRepository.findByUsername(request.getUsername()).orElseThrow(); // Find the user by username
        var jwtToken = jwtService.generateToken(user.getUsername()); // Generate JWT token
        return AuthenticationResponse.builder().token(jwtToken).build();
    } // Method to authenticate a user - returns a JWT token

    public UserResponseDto findUserByAuth(String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return new UserResponseDto();
        } else {
            String jwt = authHeader.substring(7); // Extract the JWT token from the header - removing "Bearer "
            String username = jwtService.extractUsername(jwt); // Extract the username from the JWT token
            User user = userRepository.findByUsername(username).orElseThrow();
            return new UserResponseDto(user);
        }
    } // Method to find a user by JWT token
}
