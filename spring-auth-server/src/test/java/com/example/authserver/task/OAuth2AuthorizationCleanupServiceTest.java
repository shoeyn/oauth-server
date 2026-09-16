package com.example.authserver.task;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.sql.Timestamp;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.util.ReflectionTestUtils;

@ExtendWith(MockitoExtension.class)
class OAuth2AuthorizationCleanupServiceTest {

  @Mock private JdbcTemplate jdbcTemplate;

  @InjectMocks private OAuth2AuthorizationCleanupService service;

  @BeforeEach
  void setUp() {
    ReflectionTestUtils.setField(service, "cleanupEnabled", true);
    ReflectionTestUtils.setField(service, "retentionDays", 30);
  }

  @Test
  void pruneExpiredAuthorizations_ReturnsDeletedCount_OnSuccess() {
    when(jdbcTemplate.update(
            anyString(), any(Timestamp.class), any(Timestamp.class), any(Timestamp.class)))
        .thenReturn(7);

    int deleted = service.pruneExpiredAuthorizations(30);

    assertEquals(7, deleted);
    verify(jdbcTemplate)
        .update(anyString(), any(Timestamp.class), any(Timestamp.class), any(Timestamp.class));
  }

  @Test
  void pruneExpiredAuthorizations_ReturnsZero_OnException() {
    when(jdbcTemplate.update(
            anyString(), any(Timestamp.class), any(Timestamp.class), any(Timestamp.class)))
        .thenThrow(new RuntimeException("db error"));

    int deleted = service.pruneExpiredAuthorizations(30);

    assertEquals(0, deleted);
  }

  @Test
  void scheduledCleanup_Prunes_WhenEnabled() {
    when(jdbcTemplate.update(
            anyString(), any(Timestamp.class), any(Timestamp.class), any(Timestamp.class)))
        .thenReturn(2);

    service.scheduledCleanup();

    verify(jdbcTemplate)
        .update(anyString(), any(Timestamp.class), any(Timestamp.class), any(Timestamp.class));
  }

  @Test
  void scheduledCleanup_DoesNothing_WhenDisabled() {
    ReflectionTestUtils.setField(service, "cleanupEnabled", false);

    service.scheduledCleanup();

    verifyNoInteractions(jdbcTemplate);
  }
}
