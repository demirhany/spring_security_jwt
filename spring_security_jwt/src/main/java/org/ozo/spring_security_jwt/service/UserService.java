package org.ozo.spring_security_jwt.service;

import lombok.RequiredArgsConstructor;
import org.ozo.spring_security_jwt.dto.UserResponseDto;
import org.ozo.spring_security_jwt.entity.User;
import org.ozo.spring_security_jwt.repository.UserRepository;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepository userRepository;

    public void createUser(String username, String password) {
         userRepository.save(new User(null, username, password));
    }

    public UserResponseDto getUser(String username) {
        Optional<User> user = userRepository.findByUsername(username);
        UserResponseDto userResponseDto = new UserResponseDto();
        userResponseDto.setUsername(user.map(User::getUsername).orElse(null));
        return userResponseDto;
    }
}
