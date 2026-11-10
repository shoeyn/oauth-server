package com.example.authserver.controller;

import com.example.authserver.api.UserAdminApi;
import com.example.authserver.model.AuthenticatedUserResponse;
import com.example.authserver.model.EditUserRequest;
import com.example.authserver.model.MessageResponse;
import com.example.authserver.model.UserCredentialsRequest;
import com.example.authserver.model.UserListResponse;
import com.example.authserver.security.UserSessionRevocationService;
import java.util.List;
import java.util.Map;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.RestController;

/**
 * Controller for admin operations on users.
 *
 * <p>Implements contract-first OpenAPI interface {@link UserAdminApi}. Note on passwords: The
 * client sends a SHA-256 hex digest of the plaintext password in the "password" field. This
 * controller then uses BCrypt to hash that SHA-256 digest before storing it in the database. For
 * authentication, the expected BCrypt hash is verified against the incoming SHA-256 digest.
 */
@RestController
public class UserAdminController implements UserAdminApi {

  private final PasswordEncoder passwordEncoder;
  private final JdbcTemplate jdbcTemplate;
  private final UserSessionRevocationService revocationService;

  public UserAdminController(
      JdbcTemplate jdbcTemplate, UserSessionRevocationService revocationService) {
    this.passwordEncoder = new BCryptPasswordEncoder(10);
    this.jdbcTemplate = jdbcTemplate;
    this.revocationService = revocationService;
  }

  @Autowired
  public UserAdminController(
      PasswordEncoder passwordEncoder,
      JdbcTemplate jdbcTemplate,
      UserSessionRevocationService revocationService) {
    this.passwordEncoder = passwordEncoder;
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

  @Override
  public ResponseEntity<UserListResponse> listUsers(Integer page, Integer limit) {
    int p = (page == null || page < 1) ? 1 : page;
    int l = (limit == null || limit < 1) ? 10 : limit;
    int offset = (p - 1) * l;

    List<Map<String, Object>> users =
        jdbcTemplate.queryForList(
            "SELECT id, email, is_fraud FROM app_users ORDER BY email ASC LIMIT ? OFFSET ?",
            l,
            offset);

    Integer total = jdbcTemplate.queryForObject("SELECT COUNT(*) FROM app_users", Integer.class);
    if (total == null) {
      total = 0;
    }

    int totalPages = (int) Math.ceil((double) total / l);

    return ResponseEntity.ok(
        new UserListResponse().users(users).total(total).page(p).totalPages(totalPages));
  }

  @Override
  @SuppressWarnings("unchecked")
  public ResponseEntity<MessageResponse> createUser(UserCredentialsRequest userCredentialsRequest) {
    String email = userCredentialsRequest.getEmail();
    String password = userCredentialsRequest.getPassword();

    if (email == null || email.isBlank() || password == null || password.isBlank()) {
      return (ResponseEntity<MessageResponse>)
          (ResponseEntity<?>)
              ResponseEntity.badRequest().body(Map.of("error", "Email and password required"));
    }

    try {
      String passwordHash = passwordEncoder.encode(password);

      jdbcTemplate.update(
          "INSERT INTO app_users (email, password_hash) VALUES (?, ?)", email, passwordHash);
      return ResponseEntity.status(HttpStatus.CREATED)
          .body(new MessageResponse().message("User created"));
    } catch (Exception e) {
      return (ResponseEntity<MessageResponse>)
          (ResponseEntity<?>)
              ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                  .body(Map.of("error", e.getMessage()));
    }
  }

  @Override
  @SuppressWarnings("unchecked")
  public ResponseEntity<MessageResponse> editUser(String email, EditUserRequest editUserRequest) {
    String newEmail = editUserRequest.getEmail();
    String password = editUserRequest.getPassword();

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
      return ResponseEntity.ok(new MessageResponse().message("User updated"));
    } catch (Exception e) {
      return (ResponseEntity<MessageResponse>)
          (ResponseEntity<?>)
              ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                  .body(Map.of("error", e.getMessage()));
    }
  }

  @Override
  @SuppressWarnings("unchecked")
  public ResponseEntity<MessageResponse> flagFraud(String email) {
    String userId = resolveUserId(email);
    int updated =
        jdbcTemplate.update("UPDATE app_users SET is_fraud = true WHERE email = ?", email);
    if (updated == 0) {
      return (ResponseEntity<MessageResponse>)
          (ResponseEntity<?>)
              ResponseEntity.status(HttpStatus.NOT_FOUND).body(Map.of("error", "User not found"));
    }

    // Revoke by user id: sessions/authorizations are keyed by id, not email.
    revocationService.revokeUserGlobally(userId, null, null);

    return ResponseEntity.ok(
        new MessageResponse().message("User flagged as fraud and sessions terminated"));
  }

  @Override
  @SuppressWarnings("unchecked")
  public ResponseEntity<MessageResponse> unflagFraud(String email) {
    int updated =
        jdbcTemplate.update("UPDATE app_users SET is_fraud = false WHERE email = ?", email);
    if (updated == 0) {
      return (ResponseEntity<MessageResponse>)
          (ResponseEntity<?>)
              ResponseEntity.status(HttpStatus.NOT_FOUND).body(Map.of("error", "User not found"));
    }
    return ResponseEntity.ok(new MessageResponse().message("User fraud flag removed"));
  }

  @Override
  @SuppressWarnings("unchecked")
  public ResponseEntity<MessageResponse> deleteUser(String email) {
    // Resolve id before deleting the row, then revoke sessions/authorizations by id.
    String userId = resolveUserId(email);
    revocationService.revokeUserGlobally(userId, null, null);
    int deleted = jdbcTemplate.update("DELETE FROM app_users WHERE email = ?", email);
    if (deleted == 0) {
      return (ResponseEntity<MessageResponse>)
          (ResponseEntity<?>)
              ResponseEntity.status(HttpStatus.NOT_FOUND).body(Map.of("error", "User not found"));
    }
    return ResponseEntity.ok(new MessageResponse().message("User deleted"));
  }

  @Override
  @SuppressWarnings("unchecked")
  public ResponseEntity<AuthenticatedUserResponse> authenticateUser(
      UserCredentialsRequest userCredentialsRequest) {
    String email = userCredentialsRequest.getEmail();
    String password = userCredentialsRequest.getPassword();

    if (email == null || password == null) {
      return (ResponseEntity<AuthenticatedUserResponse>)
          (ResponseEntity<?>)
              ResponseEntity.badRequest().body(Map.of("error", "Email and password required"));
    }

    List<Map<String, Object>> users =
        jdbcTemplate.queryForList(
            "SELECT id, email, password_hash, is_fraud FROM app_users WHERE email = ? LIMIT 1",
            email);

    if (users.isEmpty()) {
      return (ResponseEntity<AuthenticatedUserResponse>)
          (ResponseEntity<?>)
              ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                  .body(Map.of("error", "invalid_credentials"));
    }

    Map<String, Object> user = users.get(0);
    Boolean isFraud = (Boolean) user.get("is_fraud");

    if (Boolean.TRUE.equals(isFraud)) {
      return (ResponseEntity<AuthenticatedUserResponse>)
          (ResponseEntity<?>)
              ResponseEntity.status(HttpStatus.FORBIDDEN)
                  .body(Map.of("error", "account_suspended"));
    }

    try {
      String expectedHash = (String) user.get("password_hash");

      if (!passwordEncoder.matches(password, expectedHash)) {
        return (ResponseEntity<AuthenticatedUserResponse>)
            (ResponseEntity<?>)
                ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "invalid_credentials"));
      }

      return ResponseEntity.ok(
          new AuthenticatedUserResponse()
              .id(user.get("id").toString())
              .email((String) user.get("email"))
              .status("authenticated"));
    } catch (Exception e) {
      return (ResponseEntity<AuthenticatedUserResponse>)
          (ResponseEntity<?>)
              ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                  .body(Map.of("error", e.getMessage()));
    }
  }
}
