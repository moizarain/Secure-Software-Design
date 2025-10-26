package edu.nu.owaspapivulnlab.web;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import edu.nu.owaspapivulnlab.model.Account;
import edu.nu.owaspapivulnlab.model.AppUser;
import edu.nu.owaspapivulnlab.repo.AccountRepository;
import edu.nu.owaspapivulnlab.repo.AppUserRepository;

import java.security.Principal;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/accounts")
public class AccountController {

    private final AccountRepository accounts;
    private final AppUserRepository users;

    public AccountController(AccountRepository accounts, AppUserRepository users) {
        this.accounts = accounts;
        this.users = users;
    }

    // --- FIX 4: Data Exposure Control (DTO) ---
    // DTO to safely expose account data
    public static class AccountDto {
        private Long id;
        private String iban;
        private Double balance;

        public AccountDto(Account account) {
            this.id = account.getId();
            this.iban = account.getIban(); // IBAN might also be sensitive, but shown here
            this.balance = account.getBalance();
        }
        // Getters...
        public Long getId() { return id; }
        public String getIban() { return iban; }
        public Double getBalance() { return balance; }
    }
    
    // DTO to safely expose just the balance
    public static class BalanceDto {
        private Double balance;
        public BalanceDto(Double balance) { this.balance = balance; }
        public Double getBalance() { return balance; }
    }


    // --- FIX 3: Resource Ownership ---
    @GetMapping("/{id}/balance")
    public ResponseEntity<BalanceDto> balance(@PathVariable Long id, Principal principal) {
        Account a = accounts.findById(id).orElseThrow(() -> new RuntimeException("Account not found"));
        
        // Check if the authenticated user owns this account or is an admin
        checkOwnership(a.getOwnerUserId(), principal);

        return ResponseEntity.ok(new BalanceDto(a.getBalance()));
    }

    @PostMapping("/{id}/transfer")
    public ResponseEntity<?> transfer(@PathVariable Long id, @RequestParam Double amount, Principal principal) {
        // --- FIX 9: Input Validation ---
        if (amount == null || amount <= 0) {
            return ResponseEntity.badRequest().body(Map.of("error", "Transfer amount must be positive."));
        }

        Account a = accounts.findById(id).orElseThrow(() -> new RuntimeException("Account not found"));
        
        // --- FIX 3: Resource Ownership ---
        // Check if the authenticated user owns this account
        checkOwnership(a.getOwnerUserId(), principal);

        // --- FIX 9: Input Validation ---
        if (a.getBalance() - amount < 0) {
            return ResponseEntity.badRequest().body(Map.of("error", "Insufficient funds."));
        }

        a.setBalance(a.getBalance() - amount);
        accounts.save(a);

        // --- FIX 4: Data Exposure Control ---
        // Return the updated, safe DTO
        return ResponseEntity.ok(new AccountDto(a));
    }

    // --- FIX 4: Data Exposure Control ---
    @GetMapping("/mine")
    public ResponseEntity<List<AccountDto>> mine(Principal principal) {
        AppUser me = getAuthUser(principal);
        if (me == null) {
            return ResponseEntity.ok(Collections.emptyList());
        }
        
        List<Account> myAccounts = accounts.findByOwnerUserId(me.getId());
        
        // Map to DTOs to prevent leaking sensitive entity fields
        List<AccountDto> myAccountDtos = myAccounts.stream()
                .map(AccountDto::new)
                .collect(Collectors.toList());
                
        return ResponseEntity.ok(myAccountDtos);
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

    private void checkOwnership(Long resourceOwnerId, Principal principal) {
        if (isAdmin()) {
            return; // Admin can bypass
        }
        AppUser authUser = getAuthUser(principal);
        if (authUser == null || !authUser.getId().equals(resourceOwnerId)) {
            throw new AccessDeniedException("You do not have permission to access this resource.");
        }
    }
}