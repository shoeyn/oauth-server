package com.example.authserver.controller;

import com.example.authserver.security.UserSessionRevocationService;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Controller for admin operations on users. Note on passwords: The client sends a SHA-256 hex
 * digest of the plaintext password in the "password" field. This controller then uses BCrypt to
 * hash that SHA-256 digest before storing it in the database. For authentication, the expected
 * BCrypt hash is verified against the incoming SHA-256 digest.
 */
@RestController
@RequestMapping("/api/admin/users")
public class UserAdminController {

  private final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder(10);

  private final JdbcTemplate jdbcTemplate;
  private final UserSessionRevocationService revocationService;

  public UserAdminController(
      JdbcTemplate jdbcTemplate, UserSessionRevocationService revocationService) {
    this.jdbcTemplate = jdbcTemplate;
    this.revocationService = revocationService;
  }

  /**
   * Resolves a user's stable id (UUID) from their email. Sessions and OAuth authorizations are
   * keyed by this id (it is the Redis session {@code username} field and the OAuth {@code
   * principal_name}), NOT by email, so revocation must be performed by id. Returns null if the user
   * does not exist.
   */
  private String resolveUserId(String email) {
    try {
      List<Map<String, Object>> rows =
          jdbcTemplate.queryForList("SELECT id FROM app_users WHERE email = ? LIMIT 1", email);
      if (rows.isEmpty()) {
        return null;
      }
      Object id = rows.get(0).get("id");
      return id != null ? id.toString() : null;
    } catch (Exception e) {
      return null;
    }
  }

  @GetMapping
  public ResponseEntity<Map<String, Object>> listUsers(
      @RequestParam(defaultValue = "1") int page, @RequestParam(defaultValue = "10") int limit) {

    if (page < 1) {
      page = 1;
    }
    if (limit < 1) {
      limit = 10;
    }
    int offset = (page - 1) * limit;

    List<Map<String, Object>> users =
        jdbcTemplate.queryForList(
            "SELECT id, email, is_fraud FROM app_users ORDER BY email ASC LIMIT ? OFFSET ?",
            limit,
            offset);

    Integer total = jdbcTemplate.queryForObject("SELECT COUNT(*) FROM app_users", Integer.class);
    if (total == null) {
      total = 0;
    }

    int totalPages = (int) Math.ceil((double) total / limit);

    Map<String, Object> response = new HashMap<>();
    response.put("users", users);
    response.put("total", total);
    response.put("page", page);
    response.put("totalPages", totalPages);

    return ResponseEntity.ok(response);
  }

  @PostMapping
  public ResponseEntity<?> createUser(@RequestBody Map<String, String> payload) {
    String email = payload.get("email");
    String password = payload.get("password");

    if (email == null || email.isBlank() || password == null || password.isBlank()) {
      return ResponseEntity.badRequest().body(Map.of("error", "Email and password required"));
    }

    try {
      String passwordHash = passwordEncoder.encode(password);

      jdbcTemplate.update(
          "INSERT INTO app_users (email, password_hash) VALUES (?, ?)", email, passwordHash);
      return ResponseEntity.status(HttpStatus.CREATED).body(Map.of("message", "User created"));
    } catch (Exception e) {
      return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
          .body(Map.of("error", e.getMessage()));
    }
  }

  @PutMapping("/{email}")
  public ResponseEntity<?> editUser(
      @PathVariable String email, @RequestBody Map<String, String> payload) {
    String newEmail = payload.get("email");
    String password = payload.get("password");

    try {
      // Resolve id from the CURRENT email before any update (the email may be changing).
      String userId = resolveUserId(email);

      if (password != null && !password.isBlank()) {
        String passwordHash = passwordEncoder.encode(password);

        if (newEmail != null && !newEmail.isBlank() && !newEmail.equals(email)) {
          jdbcTemplate.update(
              "UPDATE app_users SET email = ?, password_hash = ? WHERE email = ?",
              newEmail,
              passwordHash,
              email);
          revocationService.revokeUserGlobally(userId, null, null);
        } else {
          jdbcTemplate.update(
              "UPDATE app_users SET password_hash = ? WHERE email = ?", passwordHash, email);
        }
      } else if (newEmail != null && !newEmail.isBlank() && !newEmail.equals(email)) {
        jdbcTemplate.update("UPDATE app_users SET email = ? WHERE email = ?", newEmail, email);
        revocationService.revokeUserGlobally(userId, null, null);
      }
      return ResponseEntity.ok(Map.of("message", "User updated"));
    } catch (Exception e) {
      return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
          .body(Map.of("error", e.getMessage()));
    }
  }

  @PostMapping("/{email}/fraud")
  public ResponseEntity<?> flagFraud(@PathVariable String email) {
    String userId = resolveUserId(email);
    int updated =
        jdbcTemplate.update("UPDATE app_users SET is_fraud = true WHERE email = ?", email);
    if (updated == 0) {
      return ResponseEntity.status(HttpStatus.NOT_FOUND).body(Map.of("error", "User not found"));
    }

    // Revoke by user id: sessions/authorizations are keyed by id, not email.
    revocationService.revokeUserGlobally(userId, null, null);

    return ResponseEntity.ok(Map.of("message", "User flagged as fraud and sessions terminated"));
  }

  @PostMapping("/{email}/unfraud")
  public ResponseEntity<?> unflagFraud(@PathVariable String email) {
    int updated =
        jdbcTemplate.update("UPDATE app_users SET is_fraud = false WHERE email = ?", email);
    if (updated == 0) {
      return ResponseEntity.status(HttpStatus.NOT_FOUND).body(Map.of("error", "User not found"));
    }
    return ResponseEntity.ok(Map.of("message", "User fraud flag removed"));
  }

  @DeleteMapping("/{email}")
  public ResponseEntity<?> deleteUser(@PathVariable String email) {
    // Resolve id before deleting the row, then revoke sessions/authorizations by id.
    String userId = resolveUserId(email);
    revocationService.revokeUserGlobally(userId, null, null);
    int deleted = jdbcTemplate.update("DELETE FROM app_users WHERE email = ?", email);
    if (deleted == 0) {
      return ResponseEntity.status(HttpStatus.NOT_FOUND).body(Map.of("error", "User not found"));
    }
    return ResponseEntity.ok(Map.of("message", "User deleted"));
  }

  @PostMapping("/authenticate")
  public ResponseEntity<?> authenticate(@RequestBody Map<String, String> payload) {
    String email = payload.get("email");
    String password = payload.get("password");

    if (email == null || password == null) {
      return ResponseEntity.badRequest().body(Map.of("error", "Email and password required"));
    }

    List<Map<String, Object>> users =
        jdbcTemplate.queryForList(
            "SELECT id, email, password_hash, is_fraud FROM app_users WHERE email = ? LIMIT 1",
            email);

    if (users.isEmpty()) {
      return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
          .body(Map.of("error", "invalid_credentials"));
    }

    Map<String, Object> user = users.get(0);
    Boolean isFraud = (Boolean) user.get("is_fraud");

    if (Boolean.TRUE.equals(isFraud)) {
      return ResponseEntity.status(HttpStatus.FORBIDDEN).body(Map.of("error", "account_suspended"));
    }

    try {
      String expectedHash = (String) user.get("password_hash");

      if (!passwordEncoder.matches(password, expectedHash)) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
            .body(Map.of("error", "invalid_credentials"));
      }

      return ResponseEntity.ok(
          Map.of(
              "id", user.get("id").toString(),
              "email", user.get("email"),
              "status", "authenticated"));
    } catch (Exception e) {
      return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
          .body(Map.of("error", e.getMessage()));
    }
  }
}
