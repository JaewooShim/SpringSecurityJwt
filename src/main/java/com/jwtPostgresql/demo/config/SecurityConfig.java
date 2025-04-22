package com.jwtPostgresql.demo.config;

import com.jwtPostgresql.demo.jwt.AuthEntryPointJwt;
import com.jwtPostgresql.demo.jwt.AuthTokenFilter;
import com.jwtPostgresql.demo.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity // -> enables us to customize security configuration
@EnableMethodSecurity
public class SecurityConfig {

    @Autowired
    UserRepository userRepository;

    @Autowired
    private AuthEntryPointJwt unauthorizedHandler;

//    Single, container‑managed instance
//    Spring calls your @Bean method once at startup and holds onto that one AuthTokenFilter instance.
//    Dependency injection
//    You can have Spring inject other beans into your filter (e.g. @Autowired JwtUtils jwtUtils;)
//    because it lives in the application context.
    @Bean
    public AuthTokenFilter jwtAuthTokenFilter() {
        return new AuthTokenFilter();
    }

    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests((requests) -> requests
                .requestMatchers("/public/**").permitAll()
                .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                .anyRequest().authenticated());
//                .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()

        // need to make it stateless for jwt
        http.sessionManagement(session
                -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        http.exceptionHandling(exception ->
                exception.authenticationEntryPoint(unauthorizedHandler));

        http.csrf(AbstractHttpConfigurer::disable);

        http.addFilterBefore(jwtAuthTokenFilter(), UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        return username -> userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
        authenticationProvider.setUserDetailsService(userDetailsService());
        authenticationProvider.setPasswordEncoder(passwordEncoder());
        return authenticationProvider;
    }
}
