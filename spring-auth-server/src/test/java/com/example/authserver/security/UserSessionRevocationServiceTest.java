package com.example.authserver.security;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.Cursor;
import org.springframework.data.redis.core.ScanOptions;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.test.util.ReflectionTestUtils;

@ExtendWith(MockitoExtension.class)
class UserSessionRevocationServiceTest {

  @Mock private OAuth2AuthorizationService authorizationService;

  @Mock private StringRedisTemplate redisTemplate;

  @Mock private JdbcTemplate jdbcTemplate;

  @Mock private ValueOperations<String, String> valueOperations;

  @Mock private Cursor<String> cursor;

  @InjectMocks private UserSessionRevocationService service;

  private final String redisPrefix = "session:";

  @BeforeEach
  void setUp() {
    ReflectionTestUtils.setField(service, "redisPrefix", redisPrefix);
  }

  @Test
  void testRevokeUserGlobally_UsernameProvided_DeletesFromDbAndScansRedis() {
    String username = "testuser";
    when(jdbcTemplate.update("DELETE FROM oauth2_authorization WHERE principal_name = ?", username))
        .thenReturn(3);

    when(redisTemplate.scan(any(ScanOptions.class))).thenReturn(cursor);
    when(cursor.hasNext()).thenReturn(true, true, true, false);
    when(cursor.next()).thenReturn("session:1", "session:2", "session:3");

    when(redisTemplate.opsForValue()).thenReturn(valueOperations);
    when(valueOperations.get("session:1")).thenReturn("{\"username\":\"testuser\"}");
    when(valueOperations.get("session:2")).thenReturn("{\"username\":\"otheruser\"}");
    when(valueOperations.get("session:3")).thenReturn(null);

    when(redisTemplate.delete("session:1")).thenReturn(Boolean.TRUE);

    UserSessionRevocationService.RevocationResult result =
        service.revokeUserGlobally(username, null, null);

    assertEquals(3, result.purgedAuthorizations());
    assertTrue(result.sessionEvicted());

    verify(jdbcTemplate)
        .update("DELETE FROM oauth2_authorization WHERE principal_name = ?", username);
    verify(redisTemplate).scan(any(ScanOptions.class));
    verify(redisTemplate).delete("session:1");
    verify(redisTemplate, never()).delete("session:2");
    verify(redisTemplate, never()).delete("session:3");
    verify(cursor).close(); // since try-with-resources calls close()
  }

  @Test
  void testRevokeUserGlobally_ScanThrowsException_HandlesExceptionGracefully() {
    String username = "testuser";
    when(jdbcTemplate.update("DELETE FROM oauth2_authorization WHERE principal_name = ?", username))
        .thenReturn(1);

    when(redisTemplate.scan(any(ScanOptions.class))).thenThrow(new RuntimeException("Redis down"));

    UserSessionRevocationService.RevocationResult result =
        service.revokeUserGlobally(username, null, null);

    assertEquals(1, result.purgedAuthorizations());
    assertFalse(result.sessionEvicted());
  }

  @Test
  void testRevokeUserGlobally_SingleAuthorizationProvided_RemovesAuthorization() {
    OAuth2Authorization authorization = mock(OAuth2Authorization.class);

    UserSessionRevocationService.RevocationResult result =
        service.revokeUserGlobally(null, authorization, null);

    assertEquals(1, result.purgedAuthorizations());
    assertFalse(result.sessionEvicted());

    verify(authorizationService).remove(authorization);
    verifyNoInteractions(jdbcTemplate);
    verifyNoInteractions(redisTemplate);
  }

  @Test
  void testRevokeUserGlobally_UsernameBlank_SingleAuthorizationProvided_RemovesAuthorization() {
    OAuth2Authorization authorization = mock(OAuth2Authorization.class);

    UserSessionRevocationService.RevocationResult result =
        service.revokeUserGlobally("   ", authorization, null);

    assertEquals(1, result.purgedAuthorizations());
    assertFalse(result.sessionEvicted());

    verify(authorizationService).remove(authorization);
    verifyNoInteractions(jdbcTemplate);
    verifyNoInteractions(redisTemplate);
  }

  @Test
  void testRevokeUserGlobally_NothingProvided_DoesNothing() {
    UserSessionRevocationService.RevocationResult result =
        service.revokeUserGlobally(null, null, null);

    assertEquals(0, result.purgedAuthorizations());
    assertFalse(result.sessionEvicted());

    verifyNoInteractions(authorizationService);
    verifyNoInteractions(jdbcTemplate);
    verifyNoInteractions(redisTemplate);
  }

  @Test
  void testRevokeUserGlobally_SessionIdProvided_ValidUuid_EvictsSession() {
    UUID sessionId = UUID.randomUUID();
    String sessionIdStr = sessionId.toString();

    when(redisTemplate.delete(redisPrefix + sessionIdStr)).thenReturn(Boolean.TRUE);

    UserSessionRevocationService.RevocationResult result =
        service.revokeUserGlobally(null, null, sessionIdStr);

    assertEquals(0, result.purgedAuthorizations());
    assertTrue(result.sessionEvicted());

    verify(redisTemplate).delete(redisPrefix + sessionIdStr);
  }

  @Test
  void testRevokeUserGlobally_SessionIdProvided_ValidUuidWithSpaces_EvictsSession() {
    UUID sessionId = UUID.randomUUID();
    String sessionIdStr = " " + sessionId.toString() + " ";

    when(redisTemplate.delete(redisPrefix + sessionId)).thenReturn(Boolean.FALSE);

    UserSessionRevocationService.RevocationResult result =
        service.revokeUserGlobally(null, null, sessionIdStr);

    assertEquals(0, result.purgedAuthorizations());
    assertFalse(result.sessionEvicted());

    verify(redisTemplate).delete(redisPrefix + sessionId);
  }

  @Test
  void testRevokeUserGlobally_SessionIdProvided_InvalidUuid_CatchesException() {
    String invalidSessionId = "not-a-uuid";

    UserSessionRevocationService.RevocationResult result =
        service.revokeUserGlobally(null, null, invalidSessionId);

    assertEquals(0, result.purgedAuthorizations());
    assertFalse(result.sessionEvicted());

    verifyNoInteractions(redisTemplate);
  }

  @Test
  void testRevokeUserGlobally_SessionIdProvided_RedisReturnsNull_DoesNotEvict() {
    UUID sessionId = UUID.randomUUID();
    String sessionIdStr = sessionId.toString();

    when(redisTemplate.delete(redisPrefix + sessionIdStr)).thenReturn(null);

    UserSessionRevocationService.RevocationResult result =
        service.revokeUserGlobally(null, null, sessionIdStr);

    assertEquals(0, result.purgedAuthorizations());
    assertFalse(result.sessionEvicted());

    verify(redisTemplate).delete(redisPrefix + sessionIdStr);
  }

  @Test
  void testRevokeUserGlobally_SessionIdBlank_DoesNothing() {
    UserSessionRevocationService.RevocationResult result =
        service.revokeUserGlobally(null, null, "  ");

    assertEquals(0, result.purgedAuthorizations());
    assertFalse(result.sessionEvicted());

    verifyNoInteractions(redisTemplate);
  }
}
