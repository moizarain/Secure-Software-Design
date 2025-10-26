package edu.nu.owaspapivulnlab.config;

import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder; // Import PasswordEncoder
import edu.nu.owaspapivulnlab.model.Account;
import edu.nu.owaspapivulnlab.model.AppUser;
import edu.nu.owaspapivulnlab.repo.AccountRepository;
import edu.nu.owaspapivulnlab.repo.AppUserRepository;

@Configuration
public class DataSeeder {

    // Inject the PasswordEncoder bean
    @Bean
    CommandLineRunner seed(AppUserRepository users, AccountRepository accounts, PasswordEncoder passwordEncoder) {
        return args -> {
            if (users.count() == 0) {
                
                // --- FIX 1: Password Security ---
                // Hash the passwords using BCrypt before saving
                AppUser u1 = users.save(AppUser.builder()
                        .username("alice")
                        .password(passwordEncoder.encode("alice123")) // HASHED
                        .email("alice@cydea.tech")
                        .role("USER")
                        .isAdmin(false) // This field should probably be removed (see Task 6)
                        .build());
                
                AppUser u2 = users.save(AppUser.builder()
                        .username("bob")
                        .password(passwordEncoder.encode("bob123")) // HASHED
                        .email("bob@cydea.tech")
                        .role("ADMIN")
                        .isAdmin(true) // This field should probably be removed (see Task 6)
                        .build());

                accounts.save(Account.builder().ownerUserId(u1.getId()).iban("PK00-ALICE").balance(1000.0).build());
                accounts.save(Account.builder().ownerUserId(u2.getId()).iban("PK00-BOB").balance(5000.0).build());
            }
        };
    }
}