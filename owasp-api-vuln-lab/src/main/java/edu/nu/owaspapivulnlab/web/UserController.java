package edu.nu.owaspapivulnlab.web;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder; // Import
import org.springframework.web.bind.annotation.*;
import edu.nu.owaspapivulnlab.model.AppUser;
import edu.nu.owaspapivulnlab.repo.AppUserRepository;

import java.security.Principal;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/users")
public class UserController {
    private final AppUserRepository users;
    private final PasswordEncoder passwordEncoder; // --- FIX 6 ---

    public UserController(AppUserRepository users, PasswordEncoder passwordEncoder) {
        this.users = users;
        this.passwordEncoder = passwordEncoder; // --- FIX 6 ---
    }

    // --- FIX 4: Data Exposure Control (DTO) ---
    // DTO to safely expose user data (copied from AuthController)
    public static class UserDto {
        private Long id;
        private String username;
        private String email;

        public UserDto(AppUser user) {
            this.id = user.getId();
            this.username = user.getUsername();
            this.email = user.getEmail();
        }
        // Getters...
        public Long getId() { return id; }
        public String getUsername() { return username; }
        public String getEmail() { return email; }
    }

    // --- FIX 6: Mass Assignment Prevention (DTO) ---
    // DTO for creating a user. Excludes 'role' and 'isAdmin'.
    public static class UserCreateDto {
        @NotBlank
        private String username;
        @NotBlank @Email
        private String email;
        @NotBlank @Size(min = 8)
        private String password;
        
        // Getters/Setters...
        public String getUsername() { return username; }
        public void setUsername(String username) { this.username = username; }
        public String getEmail() { return email; }
        public void setEmail(String email) { this.email = email; }
        public String getPassword() { return password; }
        public void setPassword(String password) { this.password = password; }
    }

    // --- FIX 3 (Ownership) & 4 (Data Exposure) ---
    @GetMapping("/{id}")
    public ResponseEntity<UserDto> get(@PathVariable Long id, Principal principal) {
        // Only allow admins or the user themselves to view the profile
        checkOwnershipOrAdmin(id, principal);
        
        AppUser user = users.findById(id).orElseThrow(() -> new RuntimeException("User not found"));
        
        // Return the safe DTO, not the AppUser entity
        return ResponseEntity.ok(new UserDto(user));
    }

    // --- FIX 6: Mass Assignment ---
    // NOTE: This endpoint allows any authenticated user to create another user,
    // which is a business logic flaw. It should ideally be admin-only
    // (by moving to AdminController or updating SecurityConfig).
    // However, we have fixed the *Mass Assignment* vulnerability.
    @PostMapping
    public ResponseEntity<UserDto> create(@Valid @RequestBody UserCreateDto body) {
        // Use the DTO, not the AppUser entity
        AppUser user = new AppUser();
        user.setUsername(body.getUsername());
        user.setEmail(body.getEmail());
        user.setPassword(passwordEncoder.encode(body.getPassword())); // Hash password
        
        // Set role on the server-side, not from client input
        user.setRole("ROLE_USER");
        user.setAdmin(false); 
        
        AppUser savedUser = users.save(user);
        return ResponseEntity.ok(new UserDto(savedUser));
    }

    // --- FIX 4: Data Exposure Control ---
    @GetMapping("/search")
    public ResponseEntity<List<UserDto>> search(@RequestParam String q) {
        List<AppUser> foundUsers = users.search(q);
        // Map to DTOs to hide sensitive fields (password, role)
        List<UserDto> dtos = foundUsers.stream()
                .map(UserDto::new)
                .collect(Collectors.toList());
        return ResponseEntity.ok(dtos);
    }

    // --- FIX 4: Data Exposure Control ---
    @GetMapping
    public ResponseEntity<List<UserDto>> list() {
        List<AppUser> allUsers = users.findAll();
        // Map to DTOs to hide sensitive fields (password, role)
        List<UserDto> dtos = allUsers.stream()
                .map(UserDto::new)
                .collect(Collectors.toList());
        return ResponseEntity.ok(dtos);
    }

    // --- FIX 3: Resource Ownership / FIX 2: Access Control ---
    @DeleteMapping("/{id}")
    public ResponseEntity<?> delete(@PathVariable Long id, Principal principal) {
        // Only allow an admin or the user themselves to delete the account
        checkOwnershipOrAdmin(id, principal);

        users.deleteById(id);
        Map<String, String> response = new HashMap<>();
        response.put("status", "deleted");
        return ResponseEntity.ok(response);
    }
    
    // --- Helper functions for security checks ---

    private AppUser getAuthUser(Principal principal) {
        if (principal == null) return null;
        return users.findByUsername(principal.getName()).orElse(null);
    }

    private boolean isAdmin() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        return auth != null && auth.getAuthorities().contains(new SimpleGrantedAuthority("ROLE_ADMIN"));
    }

    private void checkOwnershipOrAdmin(Long resourceUserId, Principal principal) {
        if (isAdmin()) {
            return; // Admin can bypass
        }
        AppUser authUser = getAuthUser(principal);
        if (authUser == null || !authUser.getId().equals(resourceUserId)) {
            throw new AccessDeniedException("You do not have permission to perform this action.");
        }
    }
}