package com.example.authserver.controller;

import com.example.authserver.security.UserSessionRevocationService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.util.*;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@ExtendWith(MockitoExtension.class)
public class UserAdminControllerTest {

    private MockMvc mockMvc;

    @Mock
    private JdbcTemplate jdbcTemplate;

    @Mock
    private UserSessionRevocationService revocationService;

    @InjectMocks
    private UserAdminController controller;

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder(10);

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.standaloneSetup(controller).build();
    }

    @Test
    void listUsers_success() throws Exception {
        Map<String, Object> user1 = Map.of(
                "id", UUID.randomUUID().toString(),
                "email", "alice@example.com",
                "is_fraud", false
        );
        when(jdbcTemplate.queryForList(anyString(), eq(10), eq(0)))
                .thenReturn(List.of(user1));
        when(jdbcTemplate.queryForObject(eq("SELECT COUNT(*) FROM app_users"), eq(Integer.class)))
                .thenReturn(1);

        mockMvc.perform(get("/api/admin/users?page=1&limit=10"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.total").value(1))
                .andExpect(jsonPath("$.page").value(1))
                .andExpect(jsonPath("$.totalPages").value(1))
                .andExpect(jsonPath("$.users[0].email").value("alice@example.com"));
    }

    @Test
    void listUsers_defaultParams() throws Exception {
        when(jdbcTemplate.queryForList(anyString(), eq(10), eq(0)))
                .thenReturn(Collections.emptyList());
        when(jdbcTemplate.queryForObject(eq("SELECT COUNT(*) FROM app_users"), eq(Integer.class)))
                .thenReturn(null);

        mockMvc.perform(get("/api/admin/users"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.total").value(0))
                .andExpect(jsonPath("$.page").value(1))
                .andExpect(jsonPath("$.totalPages").value(0));
    }

    @Test
    void createUser_success() throws Exception {
        Map<String, String> payload = Map.of(
                "email", "bob@example.com",
                "password", "secret123"
        );

        when(jdbcTemplate.update(anyString(), eq("bob@example.com"), anyString()))
                .thenReturn(1);

        mockMvc.perform(post("/api/admin/users")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(payload)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.message").value("User created"));

        verify(jdbcTemplate).update(
                eq("INSERT INTO app_users (email, password_hash) VALUES (?, ?)"),
                eq("bob@example.com"),
                argThat((String hash) -> passwordEncoder.matches("secret123", hash))
        );
    }

    @Test
    void createUser_validationFailure() throws Exception {
        mockMvc.perform(post("/api/admin/users")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of("email", ""))))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("Email and password required"));
    }

    @Test
    void editUser_updatePasswordAndEmail() throws Exception {
        Map<String, String> payload = Map.of(
                "email", "newalice@example.com",
                "password", "newsecret"
        );

        when(jdbcTemplate.update(anyString(), eq("newalice@example.com"), anyString(), eq("oldalice@example.com")))
                .thenReturn(1);

        mockMvc.perform(put("/api/admin/users/oldalice@example.com")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(payload)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("User updated"));

        verify(revocationService).revokeUserGlobally(eq("oldalice@example.com"), isNull(), isNull());
    }

    @Test
    void editUser_updatePasswordOnly() throws Exception {
        Map<String, String> payload = Map.of(
                "email", "alice@example.com",
                "password", "newsecret"
        );

        when(jdbcTemplate.update(anyString(), anyString(), eq("alice@example.com")))
                .thenReturn(1);

        mockMvc.perform(put("/api/admin/users/alice@example.com")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(payload)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("User updated"));

        verify(jdbcTemplate).update(
                eq("UPDATE app_users SET password_hash = ? WHERE email = ?"),
                argThat((String hash) -> passwordEncoder.matches("newsecret", hash)),
                eq("alice@example.com")
        );
    }

    @Test
    void editUser_updateEmailOnly() throws Exception {
        Map<String, String> payload = Map.of(
                "email", "newalice@example.com"
        );

        when(jdbcTemplate.update(anyString(), eq("newalice@example.com"), eq("oldalice@example.com")))
                .thenReturn(1);

        mockMvc.perform(put("/api/admin/users/oldalice@example.com")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(payload)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("User updated"));

        verify(revocationService).revokeUserGlobally(eq("oldalice@example.com"), isNull(), isNull());
    }

    @Test
    void flagFraud_userFound() throws Exception {
        when(jdbcTemplate.update(anyString(), eq("alice@example.com"))).thenReturn(1);

        mockMvc.perform(post("/api/admin/users/alice@example.com/fraud"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("User flagged as fraud and sessions terminated"));

        verify(revocationService).revokeUserGlobally(eq("alice@example.com"), isNull(), isNull());
    }

    @Test
    void flagFraud_userNotFound() throws Exception {
        when(jdbcTemplate.update(anyString(), eq("unknown@example.com"))).thenReturn(0);

        mockMvc.perform(post("/api/admin/users/unknown@example.com/fraud"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error").value("User not found"));
    }

    @Test
    void unflagFraud_userFound() throws Exception {
        when(jdbcTemplate.update(anyString(), eq("alice@example.com"))).thenReturn(1);

        mockMvc.perform(post("/api/admin/users/alice@example.com/unfraud"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("User fraud flag removed"));
    }

    @Test
    void unflagFraud_userNotFound() throws Exception {
        when(jdbcTemplate.update(anyString(), eq("unknown@example.com"))).thenReturn(0);

        mockMvc.perform(post("/api/admin/users/unknown@example.com/unfraud"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error").value("User not found"));
    }

    @Test
    void deleteUser_userFound() throws Exception {
        when(jdbcTemplate.update(anyString(), eq("alice@example.com"))).thenReturn(1);

        mockMvc.perform(delete("/api/admin/users/alice@example.com"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("User deleted"));

        verify(revocationService).revokeUserGlobally(eq("alice@example.com"), isNull(), isNull());
    }

    @Test
    void deleteUser_userNotFound() throws Exception {
        when(jdbcTemplate.update(anyString(), eq("unknown@example.com"))).thenReturn(0);

        mockMvc.perform(delete("/api/admin/users/unknown@example.com"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error").value("User not found"));
    }

    @Test
    void authenticate_success() throws Exception {
        String preHashedPassword = "prehashed_secret";
        String bcryptHash = passwordEncoder.encode(preHashedPassword);
        UUID userId = UUID.randomUUID();

        Map<String, Object> dbUser = Map.of(
                "id", userId,
                "email", "alice@example.com",
                "password_hash", bcryptHash,
                "is_fraud", false
        );

        when(jdbcTemplate.queryForList(anyString(), eq("alice@example.com")))
                .thenReturn(List.of(dbUser));

        mockMvc.perform(post("/api/admin/users/authenticate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "email", "alice@example.com",
                                "password", preHashedPassword
                        ))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(userId.toString()))
                .andExpect(jsonPath("$.email").value("alice@example.com"))
                .andExpect(jsonPath("$.status").value("authenticated"));
    }

    @Test
    void authenticate_invalidPassword() throws Exception {
        String bcryptHash = passwordEncoder.encode("correct_prehash");
        UUID userId = UUID.randomUUID();

        Map<String, Object> dbUser = Map.of(
                "id", userId,
                "email", "alice@example.com",
                "password_hash", bcryptHash,
                "is_fraud", false
        );

        when(jdbcTemplate.queryForList(anyString(), eq("alice@example.com")))
                .thenReturn(List.of(dbUser));

        mockMvc.perform(post("/api/admin/users/authenticate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "email", "alice@example.com",
                                "password", "wrong_prehash"
                        ))))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("invalid_credentials"));
    }

    @Test
    void authenticate_userNotFound() throws Exception {
        when(jdbcTemplate.queryForList(anyString(), eq("notfound@example.com")))
                .thenReturn(Collections.emptyList());

        mockMvc.perform(post("/api/admin/users/authenticate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "email", "notfound@example.com",
                                "password", "somepass"
                        ))))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("invalid_credentials"));
    }

    @Test
    void authenticate_fraudAccountSuspended() throws Exception {
        UUID userId = UUID.randomUUID();
        Map<String, Object> dbUser = Map.of(
                "id", userId,
                "email", "fraud@example.com",
                "password_hash", "anyhash",
                "is_fraud", true
        );

        when(jdbcTemplate.queryForList(anyString(), eq("fraud@example.com")))
                .thenReturn(List.of(dbUser));

        mockMvc.perform(post("/api/admin/users/authenticate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "email", "fraud@example.com",
                                "password", "somepass"
                        ))))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").value("account_suspended"));
    }

    @Test
    void authenticate_missingFields() throws Exception {
        mockMvc.perform(post("/api/admin/users/authenticate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of("email", "test@example.com"))))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("Email and password required"));
    }
}
