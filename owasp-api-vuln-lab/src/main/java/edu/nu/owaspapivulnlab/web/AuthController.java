package edu.nu.owaspapivulnlab.web;

import edu.nu.owaspapivulnlab.model.AppUser;
import edu.nu.owaspapivulnlab.repo.AppUserRepository;
import edu.nu.owaspapivulnlab.service.JwtService;
import jakarta.validation.Valid; // Import @Valid
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager; // Import
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken; // Import
import org.springframework.security.core.Authentication; // Import
import org.springframework.security.core.AuthenticationException; // Import AuthenticationException
import org.springframework.security.crypto.password.PasswordEncoder; // Import
import org.springframework.web.bind.annotation.*;

// Imports for logging
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {
    // --- Define the logger ---
    private static final Logger log = LoggerFactory.getLogger(AuthController.class);

    private final AppUserRepository users;
    private final JwtService jwt;
    private final AuthenticationManager authenticationManager;
    private final PasswordEncoder passwordEncoder;

    public AuthController(AppUserRepository users, JwtService jwt,
                          AuthenticationManager authenticationManager,
                          PasswordEncoder passwordEncoder) {
        this.users = users;
        this.jwt = jwt;
        this.authenticationManager = authenticationManager;
        this.passwordEncoder = passwordEncoder;
    }

    // --- DTOs for Secure Data Handling ---

    // DTO for signup request. Only contains fields a user should provide.
    public static class SignupRequestDto {
        @NotBlank(message = "Username is required")
        private String username;

        @NotBlank(message = "Email is required")
        @Email(message = "Invalid email format")
        private String email;

        @NotBlank(message = "Password is required")
        @Size(min = 8, message = "Password must be at least 8 characters long")
        private String password;

        // Getters and Setters...
        public String getUsername() { return username; }
        public void setUsername(String username) { this.username = username; }
        public String getEmail() { return email; }
        public void setEmail(String email) { this.email = email; }
        public String getPassword() { return password; }
        public void setPassword(String password) { this.password = password; }
    }

    // DTO for returning non-sensitive user data
    public static class UserDto {
        private Long id;
        private String username;
        private String email;

        public UserDto(AppUser user) {
            this.id = user.getId();
            this.username = user.getUsername();
            this.email = user.getEmail();
        }

        // Getters and Setters...
        public Long getId() { return id; }
        public void setId(Long id) { this.id = id; }
        public String getUsername() { return username; }
        public void setUsername(String username) { this.username = username; }
        public String getEmail() { return email; }
        public void setEmail(String email) { this.email = email; }
    }

    // DTO for a successful login response
    public static class LoginResponseDto {
        private String token;
        private UserDto user;

        public LoginResponseDto(String token, UserDto user) {
            this.token = token;
            this.user = user;
        }

        // Getters and Setters...
        public String getToken() { return token; }
        public void setToken(String token) { this.token = token; }
        public UserDto getUser() { return user; }
        public void setUser(UserDto user) { this.user = user; }
    }

    // LoginReq DTO
    public static class LoginReq {
        @NotBlank
        private String username;
        @NotBlank
        private String password;
        // ... getters/setters ...
        public String username() { return username; }
        public String password() { return password; }
        public void setUsername(String username) { this.username = username; }
        public void setPassword(String password) { this.password = password; }
    }


    // --- Signup Endpoint ---
    @PostMapping("/signup")
    public ResponseEntity<?> signup(@Valid @RequestBody SignupRequestDto signupRequest) {
        if (users.findByUsername(signupRequest.getUsername()).isPresent()) {
            return ResponseEntity.badRequest().body(Map.of("error", "Username is already taken"));
        }
        if (users.findByEmail(signupRequest.getEmail()).isPresent()) {
            return ResponseEntity.badRequest().body(Map.of("error", "Email is already in use"));
        }

        AppUser newUser = new AppUser();
        newUser.setUsername(signupRequest.getUsername());
        newUser.setEmail(signupRequest.getEmail());
        newUser.setPassword(passwordEncoder.encode(signupRequest.getPassword()));
        newUser.setRole("ROLE_USER");
        newUser.setAdmin(false);

        AppUser savedUser = users.save(newUser);

        return ResponseEntity.ok(new UserDto(savedUser));
    }

    // --- Login Endpoint with Logging ---
    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginReq req) {
        log.info("Attempting login for user: {}", req.username()); // Log entry
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(req.username(), req.password())
            );
            log.info("Authentication successful for user: {}", authentication.getName()); // Log success

            // Find user, generate token, return DTO
            AppUser user = users.findByUsername(authentication.getName()).orElseThrow();
            Map<String, Object> claims = new HashMap<>();
            claims.put("role", user.getRole());
            String token = jwt.issue(user.getUsername(), claims); // Assuming jwt.issue exists and is correct
            UserDto userDto = new UserDto(user);
            return ResponseEntity.ok(new LoginResponseDto(token, userDto));

        } catch (AuthenticationException e) { // Catch specific AuthenticationException
            log.error("Authentication failed for user {}: {}", req.username(), e.getMessage()); // Log failure reason
            Map<String, String> error = new HashMap<>();
            error.put("error", "invalid credentials");
            return ResponseEntity.status(401).body(error);
        } catch (Exception e) { // Catch any other unexpected errors
             log.error("An unexpected error occurred during login for user {}:", req.username(), e);
             Map<String, String> error = new HashMap<>();
             error.put("error", "internal server error during login");
             return ResponseEntity.status(500).body(error);
        }
    }
}