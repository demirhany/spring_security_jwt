package org.ozo.spring_security_jwt.controller;

import lombok.RequiredArgsConstructor;
import org.ozo.spring_security_jwt.dto.UserResponseDto;
import org.ozo.spring_security_jwt.service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/users")
public class UserController {
    private final UserService userService;

    @GetMapping("/me")
    public ResponseEntity<UserResponseDto> getUser(
            @RequestHeader("Authorization") String authHeader) {
        return ResponseEntity.ok(userService.getUser(authHeader));
    } // getUser

    @GetMapping("")
    public ResponseEntity<List<UserResponseDto>> getUsers() {
        return ResponseEntity.ok(userService.getUsers());
    } // getUsers
}
