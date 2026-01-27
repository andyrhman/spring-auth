package com.myspring.spring_auth.config;

import com.myspring.spring_auth.security.JwtUtil;
import com.myspring.spring_auth.security.JwtAuthenticationFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
public class SecurityConfig {

    private final JwtUtil jwtUtil;

    public SecurityConfig(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new Argon2PasswordEncoder(16, 32, 1, 1 << 16, 3);
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        // Jwt filter
        JwtAuthenticationFilter jwtFilter = new JwtAuthenticationFilter(jwtUtil);

        http
                // disable CSRF for stateless API (if you use browser flows storing refresh in
                // cookie,
                // you need to apply CSRF protections or use SameSite + double-submit CSRF, see
                // notes)
                .csrf(csrf -> csrf.disable())

                .sessionManagement(sess -> sess.sessionCreationPolicy(
                        org.springframework.security.config.http.SessionCreationPolicy.STATELESS))

                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/**", "/api/auth/**", "/actuator/health", "/health-check").permitAll()
                        .anyRequest().authenticated())

                // make sure JWT filter runs before UsernamePasswordAuthenticationFilter
                .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}