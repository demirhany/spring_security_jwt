package org.ozo.spring_security_jwt.dto;

import lombok.Data;
import org.ozo.spring_security_jwt.entity.User;

@Data
public class UserResponseDto {
    private String username;

    public UserResponseDto() {
    }

    public UserResponseDto(User user) {
        this.username = user.getUsername();
    }
}
