package edu.nu.owaspapivulnlab;

import com.fasterxml.jackson.databind.ObjectMapper;
import edu.nu.owaspapivulnlab.model.AppUser;
import edu.nu.owaspapivulnlab.repo.AppUserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Map;

import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
public class SecurityTests {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private AppUserRepository appUserRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private ObjectMapper objectMapper;

    // We'll create two test users: 'test-user' (ID 1) and 'other-user' (ID 2)
    @BeforeEach
    void setup() {
        // Clear the repository to ensure clean tests
        appUserRepository.deleteAll();

        // Create a standard user (ROLE_USER)
        AppUser user = new AppUser();
        user.setUsername("test-user");
        user.setEmail("user@test.com");
        user.setPassword(passwordEncoder.encode("password123"));
        user.setRole("ROLE_USER");
        appUserRepository.save(user);

        // Create another standard user (ROLE_USER)
        AppUser otherUser = new AppUser();
        otherUser.setUsername("other-user");
        otherUser.setEmail("other@test.com");
        otherUser.setPassword(passwordEncoder.encode("password123"));
        otherUser.setRole("ROLE_USER");
        appUserRepository.save(otherUser);

        // Create an admin user (ROLE_ADMIN)
        AppUser admin = new AppUser();
        admin.setUsername("test-admin");
        admin.setEmail("admin@test.com");
        admin.setPassword(passwordEncoder.encode("adminpass"));
        admin.setRole("ROLE_ADMIN");
        appUserRepository.save(admin);
    }

    // --- Task 2: Access Control Test ---
    @Test
    void testAccessSecureEndpoint_DeniesAnonymous() throws Exception {
        // Test that /api/users/{id} is protected (example)
        mockMvc.perform(get("/api/users/1")) // Assuming user ID 1 exists from setup
                // --- FIX: Anonymous users should get 403 Forbidden on protected endpoints ---
                .andExpect(status().isForbidden());
    }

    // --- Task 2: Access Control Test ---
    @Test
    @WithMockUser(username = "test-user", roles = {"USER"})
    void testAdminEndpoint_DeniesUserRole() throws Exception {
        // Test that a normal USER cannot access an admin endpoint
        // You might need to create an actual endpoint in AdminController for this
        mockMvc.perform(get("/api/admin/some-endpoint")) 
                .andExpect(status().isForbidden());
    }

    // --- Task 3: Resource Ownership Test ---
    @Test
    @WithMockUser(username = "test-user", roles = {"USER"})
    void testResourceOwnership_DeniesAccessToOtherUser() throws Exception {
        // 'test-user' is authenticated. Get the ID of 'other-user'.
        Long otherUserId = appUserRepository.findByUsername("other-user").get().getId();

        // 'test-user' tries to get '/api/users/{otherUserId}'
        mockMvc.perform(get("/api/users/" + otherUserId))
                .andExpect(status().isForbidden());
    }

    // --- Task 3: Resource Ownership Test ---
    @Test
    @WithMockUser(username = "test-user", roles = {"USER"})
    void testResourceOwnership_AllowsAccessToOwnUser() throws Exception {
        // 'test-user' is authenticated. Get their own ID.
        Long selfUserId = appUserRepository.findByUsername("test-user").get().getId();

        // 'test-user' tries to get '/api/users/{selfUserId}'
        mockMvc.perform(get("/api/users/" + selfUserId))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username", is("test-user")));
    }

    // --- Task 1 & 4: Password Hashing & Data Exposure Test ---
    @Test
    void testLogin_SuccessWithHashedPassword_ReturnsSafeDto() throws Exception {
        Map<String, String> loginRequest = Map.of(
                "username", "test-user",
                "password", "password123"
        );

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token", notNullValue())) // 1. Check token is returned
                .andExpect(jsonPath("$.user.username", is("test-user"))) // 2. Check DTO is returned
                .andExpect(jsonPath("$.user.password").doesNotExist()); // 3. Check password is NOT returned
    }

    // --- Task 6: Mass Assignment Prevention Test ---
    @Test
    void testSignup_PreventsMassAssignmentOfRole() throws Exception {
        // This malicious payload tries to set the role to ADMIN
        // Replaced text block with a standard string to fix Java 15 error
        String maliciousSignupRequest = "{"
            + "\"username\": \"malicious-user\","
            + "\"email\": \"malicious@test.com\","
            + "\"password\": \"password123\","
            + "\"role\": \"ADMIN\","
            + "\"admin\": true"
            + "}";

        mockMvc.perform(post("/api/auth/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(maliciousSignupRequest))
                .andExpect(status().isOk());

        // Verify the user in the database
        AppUser newUser = appUserRepository.findByUsername("malicious-user").get();
        // Check that the server assigned ROLE_USER, ignoring the malicious payload
        assertEquals("ROLE_USER", newUser.getRole());
    }
}