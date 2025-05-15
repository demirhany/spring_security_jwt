package org.ozo.spring_security_jwt.controller;

import lombok.RequiredArgsConstructor;
import org.ozo.spring_security_jwt.dto.AuthenticationRequest;
import org.ozo.spring_security_jwt.dto.AuthenticationResponse;
import org.ozo.spring_security_jwt.dto.UserCreateRequest;
import org.ozo.spring_security_jwt.service.AuthenticationService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import static org.springframework.http.ResponseEntity.ok;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/auth")
public class AuthenticationController {

    private final AuthenticationService authenticationService;

    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponse> register(@RequestBody UserCreateRequest request) {
        return ok(authenticationService.register(request));
    } // register

    @PostMapping("/login")
    public ResponseEntity<AuthenticationResponse> login(@RequestBody AuthenticationRequest request) {
        return ok(authenticationService.authenticate(request));
    } // login
}
