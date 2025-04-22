package com.jwtPostgresql.demo.DTO;

import com.jwtPostgresql.demo.model.Role;

public record UserDto(String username, String password, Role role) {
}
