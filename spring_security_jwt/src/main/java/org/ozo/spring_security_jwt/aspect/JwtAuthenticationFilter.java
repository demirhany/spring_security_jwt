package org.ozo.spring_security_jwt.aspect;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.ozo.spring_security_jwt.service.JwtService;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * JwtAuthenticationFilter is a filter that checks for JWT tokens in the request headers.
 * If a valid token is found, it sets the authentication in the security context.
 * This filter is executed once per request.
 */

@Configuration
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final JwtService jwtService; // Service to handle JWT operations
    private final UserDetailsService userDetailsService; // Service to load user details

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain) throws ServletException, IOException {
        final String authHeader = request.getHeader("Authorization"); // Get the Authorization header
        final String jwt; // JWT token
        final String username; // Username extracted from the token
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        } // if no auth header or invalid format
        jwt = authHeader.substring(7);
        username = jwtService.extractUsername(jwt); // Extract username from the token
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);
            if (jwtService.isTokenValid(jwt, userDetails)) {
                UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities()
                ); // Create an authentication token
                authenticationToken.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request)
                ); // Set the authentication details
                SecurityContextHolder.getContext().setAuthentication(authenticationToken); // Set the authentication in the context
            } // if token is valid
        } // if username is not null and no authentication in context
        filterChain.doFilter(request, response);
    }
} // JwtAuthenticationFilter
