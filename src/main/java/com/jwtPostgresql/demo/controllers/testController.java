package com.jwtPostgresql.demo.controllers;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
public class testController {
    @PreAuthorize("hasRole('USER')")
    @GetMapping("/hello")
    public String helloUser() {
        return "Hello, user";
    }

    @PreAuthorize("isAuthenticated()")
    @GetMapping("/ping")
    public String ping() { return "pong"; }

    @GetMapping("/profile")
    public ResponseEntity<?> getUserProfile() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();

        Map<String, Object> profile = new HashMap<>();
        profile.put("username", userDetails.getUsername());
        profile.put("roles", userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList());
        profile.put("message", "This is user-specific content from backend");
        return ResponseEntity.ok(profile);
    }
}
