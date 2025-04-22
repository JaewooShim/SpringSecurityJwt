package com.jwtPostgresql.demo.controllers;

import com.jwtPostgresql.demo.DTO.SignInDto;
import com.jwtPostgresql.demo.DTO.TokenDto;
import com.jwtPostgresql.demo.DTO.UserDto;
import com.jwtPostgresql.demo.jwt.JwtUtils;
import com.jwtPostgresql.demo.model.User;
import com.jwtPostgresql.demo.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Role;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/public")
public class UserController {

    @Autowired
    UserRepository userRepository;

    @Autowired
    PasswordEncoder passwordEncoder;

    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    JwtUtils jwtUtils;

    @PostMapping("/signup")
    public ResponseEntity<?> signUp(@RequestBody UserDto userDto) {
        if (userRepository.existsByUsername(userDto.username())) {
            return ResponseEntity.badRequest().body("Username already exists");
        }
        // password encoder!!
        User user = new User(userDto.username(), passwordEncoder.encode(userDto.password()), userDto.role());
        userRepository.save(user);
        return ResponseEntity.ok("User created successfully");
    }

    @PostMapping("/signin")
    public ResponseEntity<?> signInUser(@RequestBody SignInDto signInDto) {
        Authentication authentication;

        try {
            authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(signInDto.username(), signInDto.password())
            );
        } catch (AuthenticationException e) {
            System.err.println(e.getMessage());

            Map<String, Object> map = new HashMap<>();
            map.put("message", "Bad credentials");
            map.put("status", false);
            return new ResponseEntity<Object>(map, HttpStatus.NOT_FOUND);
        }

        SecurityContextHolder.getContext().setAuthentication(authentication);

        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        // what is lombok?
        String jwt = jwtUtils.generateTokenFromUsername(userDetails);
        List<String> roles = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList();

        TokenDto tokenDto = new TokenDto(jwt, userDetails.getUsername(), roles);
        return ResponseEntity.ok(tokenDto);
    }
}
