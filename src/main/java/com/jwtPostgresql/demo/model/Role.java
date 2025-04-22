package com.jwtPostgresql.demo.model;

public enum Role {
    ROLE_USER("ROLE_USER"),
    ROLE_ADMIN("ROLE_ADMIN"),
    ROLE_ANONYMOUS("ROLE_ANONYMOUS");

    private final String role;

    Role(String role) {
        this.role = role;
    }

    public String getRole() {
        return this.role;
    }
}
