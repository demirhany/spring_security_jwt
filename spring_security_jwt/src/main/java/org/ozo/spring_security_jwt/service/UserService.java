package org.ozo.spring_security_jwt.service;

import lombok.RequiredArgsConstructor;
import org.ozo.spring_security_jwt.dto.UserResponseDto;
import org.ozo.spring_security_jwt.entity.User;
import org.ozo.spring_security_jwt.repository.UserRepository;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepository userRepository; // Repository to interact with the database
    private final AuthenticationService authenticationService; // Service to handle authentication

    public UserResponseDto getUser(String authHeader) { // Method to get user details
        return authenticationService.findUserByAuth(authHeader);
    }

    public List<UserResponseDto> getUsers() { // Method to get all users
        List<User> users = userRepository.findAll();
        if (users.isEmpty()) {
            return List.of();
        } else {
            return users.stream()
                    .map(UserResponseDto::new)
                    .toList();
        }
    }
}
