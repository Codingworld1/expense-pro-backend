package com.expensepro.expensemanagement.security;

import java.util.Arrays;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Configuration
public class SecurityConfig {


private final JwtAuthenticationFilter jwtAuthenticationFilter;

private final OAuth2SuccessHandler oAuth2SuccessHandler;

public SecurityConfig(JwtAuthenticationFilter jwtAuthenticationFilter, OAuth2SuccessHandler oAuth2SuccessHandler) {
    this.jwtAuthenticationFilter = jwtAuthenticationFilter;
    this.oAuth2SuccessHandler = oAuth2SuccessHandler;
}

@Bean
public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http
        .csrf(csrf -> csrf.disable())
        .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .authorizeHttpRequests(auth -> auth
            .requestMatchers("/api/auth/**", "/oauth2/**", "/login**").permitAll()
            .anyRequest().authenticated()
        )
        .cors(corsCustomizer -> corsCustomizer.configurationSource(corsConfigurationSource()))
        .oauth2Login(oauth2 -> oauth2
            .successHandler(oAuth2SuccessHandler)
        )
        .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

    return http.build();
}


@Bean
public PasswordEncoder passwordEncoder() {
    // BCryptPasswordEncoder for hashing passwords
    return new BCryptPasswordEncoder();
}

@Bean
public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
    // AuthenticationManager used for authentication via JWT
    return config.getAuthenticationManager();
}

@Bean
public UrlBasedCorsConfigurationSource corsConfigurationSource() {
    // CORS configuration to allow frontend access
    CorsConfiguration configuration = new CorsConfiguration();
    configuration.setAllowedOrigins(Arrays.asList("http://localhost:3000"));  // Allow frontend to access API
    configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE"));  // Allow these HTTP methods
    configuration.setAllowedHeaders(Arrays.asList("Authorization", "Content-Type"));  // Allow specific headers
    configuration.setAllowCredentials(true);  // Allow credentials (cookies, auth headers)

    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/**", configuration);  // Apply CORS settings to all endpoints
    return source;
}


}
