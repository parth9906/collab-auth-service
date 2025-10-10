package com.parth_collab.auth_service.dto;

import com.parth_collab.auth_service.model.User;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
public class UserDTO {
    private String id;
    private String username;
    private String email;
    private String role;

    public UserDTO(User user) {
        this.id = user.getId();
        this.username = user.getUsername();
        this.email = user.getEmail();
        this.role = user.getRole();
    }
}
