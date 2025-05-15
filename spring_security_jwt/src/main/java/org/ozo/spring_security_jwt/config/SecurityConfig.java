package org.ozo.spring_security_jwt.config;

import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.ozo.spring_security_jwt.aspect.JwtAuthenticationFilter;
import org.ozo.spring_security_jwt.repository.UserRepository;
import org.ozo.spring_security_jwt.service.JwtService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * Security configuration class for the application.
 * <p>
 * This class configures the security settings for the application, including authentication and authorization.
 * It uses JWT for stateless authentication and BCrypt for password encoding.
 * Note that CSRF protection is disabled for simplicity and CORS is not configured.
 * </p>
 */

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {
    private final UserRepository userRepository; // repository for user data
    private final JwtService jwtService; // JWT service for token generation and validation

    @Bean
    public UserDetailsService userDetailsService() {
        return username -> userRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalArgumentException("User not found with username: " + username));
    } // userDetailsService

    @Bean
    public SecurityFilterChain securityFilterChain (
            HttpSecurity http,
            UserDetailsService userDetailsService,
            AuthenticationProvider authenticationProvider
    ) throws Exception {
        http.csrf(AbstractHttpConfigurer::disable); // disable CSRF protection
        http.authorizeHttpRequests(auth -> auth
                        // endpoint authorization
                        .requestMatchers("/api/auth/login", "/api/auth/register").permitAll() // public endpoints
                        .anyRequest().authenticated() // all other endpoints require authentication
                )
                .sessionManagement((sessionManagement) ->
                        sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS)) // no session management
                .authenticationProvider(authenticationProvider); // use custom authentication provider
        http.exceptionHandling(httpSecurityExceptionHandlingConfigurer ->
                httpSecurityExceptionHandlingConfigurer.authenticationEntryPoint((request, response, authException) -> {
                            if (request.getHeader("Authorization") == null) { // if no auth header
                                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, authException.getMessage()); // send 401
                            } else {
                                response.sendError(HttpServletResponse.SC_FORBIDDEN, authException.getMessage()); // send 403
                            }
                        }
                ));
        JwtAuthenticationFilter jwtAuthenticationFilter = new JwtAuthenticationFilter(jwtService, userDetailsService); // create filter
        http.addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class); // add filter to chain
        return http.build();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration)
            throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    } // authenticationManager

    @Bean
    public AuthenticationProvider authenticationProvider(UserDetailsService userDetailsService) {
        DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider(); // use DaoAuthenticationProvider
        daoAuthenticationProvider.setUserDetailsService(userDetailsService); // use custom user details service
        daoAuthenticationProvider.setPasswordEncoder(passwordEncoder()); // use BCryptPasswordEncoder
        return daoAuthenticationProvider;
    } // authenticationProvider

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    } // passwordEncoder
}
