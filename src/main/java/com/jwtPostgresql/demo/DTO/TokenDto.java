package com.jwtPostgresql.demo.DTO;

import java.util.List;

public record TokenDto(String jwtToken, String username, List<String> roles) {
}
