package edu.nu.owaspapivulnlab.config;

// Import slf4j libraries for logging
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

// --- Imports needed for AuthenticationProvider/Manager ---
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.core.userdetails.User; // Import User builder
import edu.nu.owaspapivulnlab.repo.AppUserRepository; // Import repository
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder; // Import AuthenticationManagerBuilder
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity; // Import EnableWebSecurity
// --- End imports ---

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager; // Import AuthenticationManager
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Base64;
import java.util.Collections;
import javax.crypto.SecretKey;

@Configuration
@EnableWebSecurity // Add this annotation
public class SecurityConfig {

    // --- Inject AppUserRepository ---
    private final AppUserRepository appUserRepository;

    // --- Constructor Injection ---
    public SecurityConfig(AppUserRepository appUserRepository) {
        this.appUserRepository = appUserRepository;
    }

    // --- FIX 7: JWT Hardening ---
    @Value("${jwt.secret}")
    private String secret;
    @Value("${jwt.issuer}")
    private String issuer;
    @Value("${jwt.audience}")
    private String audience;

    // --- FIX 1: Password Security ---
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // --- FIX: Add UserDetailsService Bean ---
    @Bean
    public UserDetailsService userDetailsService() {
        return username -> {
            edu.nu.owaspapivulnlab.model.AppUser appUser = appUserRepository.findByUsername(username) // Use the injected repository
                    .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));
            return User.withUsername(appUser.getUsername())
                       .password(appUser.getPassword()) // Password here is the HASHED one
                       .authorities(new SimpleGrantedAuthority(appUser.getRole())) // Or authorities() for multiple roles
                       .build();
        };
    }

    // --- FIX: Replace the AuthenticationManager Bean ---
    /* Remove this one:
     @Bean
     public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
         return authConfig.getAuthenticationManager();
     }
    */

    // --- Add this NEW AuthenticationManager Bean ---
    @Bean
    public AuthenticationManager authenticationManager(HttpSecurity http) throws Exception {
        AuthenticationManagerBuilder authenticationManagerBuilder =
            http.getSharedObject(AuthenticationManagerBuilder.class);
        authenticationManagerBuilder
            .userDetailsService(userDetailsService()) // Use our UserDetailsService
            .passwordEncoder(passwordEncoder());      // Use our PasswordEncoder
        return authenticationManagerBuilder.build();
    }


    // --- FIX 2: Access Control ---
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable())
            .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

            // Removed explicit .userDetailsService() and .authenticationProvider() from here

            .authorizeHttpRequests(reg -> reg
                // 1. Public endpoints
                .requestMatchers("/api/auth/**", "/h2-console/**").permitAll()

                // 2. Admin endpoints (must come BEFORE general rules)
                .requestMatchers("/api/admin/**").hasRole("ADMIN")

                // 3. Authenticated user endpoints
                // REMOVED: .requestMatchers(HttpMethod.GET, "/api/**").permitAll()
                .requestMatchers("/api/users/**", "/api/accounts/**").hasAnyRole("USER", "ADMIN")

                // 4. Deny all other requests by default
                .anyRequest().authenticated()
            )

            .headers(h -> h.frameOptions(f -> f.disable())) // allow H2 console

            .addFilterBefore(new JwtFilter(secret, issuer, audience), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    // --- FIX 7: JWT Hardening & FIX 8: Error Handling ---
    static class JwtFilter extends OncePerRequestFilter {

        // --- FIX: Define the logger ---
        private static final Logger logger = LoggerFactory.getLogger(JwtFilter.class);

        private final SecretKey secretKey;
        private final String issuer;
        private final String audience;

        JwtFilter(String secret, String issuer, String audience) {
            this.secretKey = Keys.hmacShaKeyFor(Base64.getDecoder().decode(secret));
            this.issuer = issuer;
            this.audience = audience;
        }

        @Override
        protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
                throws ServletException, IOException {
            String auth = request.getHeader("Authorization");
            if (auth != null && auth.startsWith("Bearer ")) {
                String token = auth.substring(7);
                try {
                    // --- FIX 7: JWT Hardening ---
                    // Validate signature, expiry, issuer, and audience
                    Claims c = Jwts.parserBuilder()
                            .setSigningKey(secretKey)
                            .requireIssuer(issuer)
                            .requireAudience(audience)
                            .build()
                            .parseClaimsJws(token)
                            .getBody();

                    String user = c.getSubject();
                    String role = (String) c.get("role"); // Assuming role is in the token

                    // --- FIX: Corrected typo and ambiguous 'null' ---
                    UsernamePasswordAuthenticationToken authn = new UsernamePasswordAuthenticationToken(user, (Object) null,
                            role != null ? Collections.singletonList(new SimpleGrantedAuthority("ROLE_" + role)) : Collections.emptyList());

                    SecurityContextHolder.getContext().setAuthentication(authn);

                } catch (JwtException e) {
                    // --- FIX 8: Error Handling ---
                    // This will now work since 'logger' is defined
                    logger.warn("JWT processing failed: " + e.getMessage());
                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    response.getWriter().write("Invalid Token");
                    return; // Stop the filter chain
                }
            }
            chain.doFilter(request, response);
        }
    }
}