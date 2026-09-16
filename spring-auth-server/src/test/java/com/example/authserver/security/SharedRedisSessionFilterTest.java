package com.example.authserver.security;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.*;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import tools.jackson.databind.json.JsonMapper;

@ExtendWith(MockitoExtension.class)
public class SharedRedisSessionFilterTest {

  @Mock private StringRedisTemplate redisTemplate;
  @Mock private ValueOperations<String, String> valueOperations;
  @Mock private HttpServletRequest request;
  @Mock private HttpServletResponse response;
  @Mock private FilterChain filterChain;
  @Mock private HttpSession httpSession;

  private SharedRedisSessionFilter filter;
  private final String redisPrefix = "test:prefix:";

  @BeforeEach
  void setUp() {
    SecurityContextHolder.clearContext();
    filter = new SharedRedisSessionFilter(redisTemplate, redisPrefix);
  }

  @AfterEach
  void tearDown() {
    SecurityContextHolder.clearContext();
  }

  @Test
  void testConstructors() {
    SharedRedisSessionFilter f1 = new SharedRedisSessionFilter(redisTemplate, "prefix");
    SharedRedisSessionFilter f2 = new SharedRedisSessionFilter(redisTemplate, null, "prefix");
    SharedRedisSessionFilter f3 =
        new SharedRedisSessionFilter(redisTemplate, JsonMapper.shared(), "prefix");
    assertNotNull(f1);
    assertNotNull(f2);
    assertNotNull(f3);
  }

  @Test
  void shouldNotFilter_skippedPaths() {
    String[] paths = {
      "/oauth2/token",
      "/oauth2/par",
      "/oauth2/jwks",
      "/oauth2/introspect",
      "/oauth2/revoke",
      "/.well-known/foo",
      "/actuator/health"
    };
    for (String path : paths) {
      when(request.getRequestURI()).thenReturn(path);
      assertTrue(filter.shouldNotFilter(request), "Should not filter path: " + path);
    }
  }

  @Test
  void doFilterInternal_WithNullRoles_Succeeds() throws Exception {
    String sessionId = UUID.randomUUID().toString();
    when(request.getCookies())
        .thenReturn(new Cookie[] {new Cookie(SharedRedisSessionFilter.COOKIE_NAME, sessionId)});
    when(request.getRequestURI()).thenReturn("/some-endpoint");
    when(redisTemplate.opsForValue()).thenReturn(valueOperations);

    // JSON without roles
    String json = "{\"username\":\"user1\",\"email\":\"user1@test.com\",\"name\":\"User One\"}";
    lenient().when(valueOperations.get(anyString())).thenReturn(json);

    filter.doFilter(request, response, filterChain);

    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    assertNotNull(auth);
    assertEquals("user1", auth.getName());
  }

  @Test
  void shouldNotFilter_interactivePaths() {
    when(request.getRequestURI()).thenReturn("/oauth2/authorize");
    assertFalse(filter.shouldNotFilter(request));
  }

  @Test
  void doFilterInternal_noCookies() throws Exception {
    when(request.getCookies()).thenReturn(null);
    when(request.getSession(false)).thenReturn(null);

    filter.doFilterInternal(request, response, filterChain);

    verify(filterChain).doFilter(request, response);
    assertNull(SecurityContextHolder.getContext().getAuthentication());
  }

  @Test
  void doFilterInternal_cookiesPresentButNoSharedSessionId() throws Exception {
    when(request.getCookies()).thenReturn(new Cookie[] {new Cookie("OTHER_COOKIE", "value")});
    when(request.getSession(false)).thenReturn(httpSession);

    filter.doFilterInternal(request, response, filterChain);

    verify(httpSession).invalidate();
    verify(filterChain).doFilter(request, response);
    assertNull(SecurityContextHolder.getContext().getAuthentication());
  }

  @Test
  void doFilterInternal_malformedSessionIdLength() throws Exception {
    String badSessionId = "too-short";
    when(request.getCookies())
        .thenReturn(new Cookie[] {new Cookie("SHARED_SESSION_ID", badSessionId)});
    when(request.getSession(false)).thenReturn(null);

    filter.doFilterInternal(request, response, filterChain);

    verify(response)
        .addCookie(
            argThat(
                c ->
                    c.getName().equals("SHARED_SESSION_ID")
                        && c.getMaxAge() == 0
                        && "/".equals(c.getPath())
                        && c.isHttpOnly()));
    verify(filterChain).doFilter(request, response);
  }

  @Test
  void doFilterInternal_malformedSessionIdNotUuid() throws Exception {
    String badSessionId = "123456789012345678901234567890123456"; // length 36 but not a valid uuid
    when(request.getCookies())
        .thenReturn(new Cookie[] {new Cookie("SHARED_SESSION_ID", badSessionId)});
    when(request.getSession(false)).thenReturn(null);

    filter.doFilterInternal(request, response, filterChain);

    verify(response)
        .addCookie(argThat(c -> c.getName().equals("SHARED_SESSION_ID") && c.getMaxAge() == 0));
    verify(filterChain).doFilter(request, response);
  }

  @Test
  void doFilterInternal_validSessionId_noRedisSession() throws Exception {
    UUID sessionId = UUID.randomUUID();
    when(request.getCookies())
        .thenReturn(new Cookie[] {new Cookie("SHARED_SESSION_ID", sessionId.toString())});
    when(redisTemplate.opsForValue()).thenReturn(valueOperations);
    when(valueOperations.get(redisPrefix + sessionId)).thenReturn(null);
    when(request.getSession(false)).thenReturn(null);

    filter.doFilterInternal(request, response, filterChain);

    verify(filterChain).doFilter(request, response);
    verify(response)
        .addCookie(argThat(c -> c.getName().equals("SHARED_SESSION_ID") && c.getMaxAge() == 0));
  }

  @Test
  void doFilterInternal_validSessionId_blankRedisSession() throws Exception {
    UUID sessionId = UUID.randomUUID();
    when(request.getCookies())
        .thenReturn(new Cookie[] {new Cookie("SHARED_SESSION_ID", sessionId.toString())});
    when(redisTemplate.opsForValue()).thenReturn(valueOperations);
    when(valueOperations.get(redisPrefix + sessionId)).thenReturn("   ");
    when(request.getSession(false)).thenReturn(null);

    filter.doFilterInternal(request, response, filterChain);

    verify(filterChain).doFilter(request, response);
  }

  @Test
  void doFilterInternal_validSessionId_invalidJsonInRedis() throws Exception {
    UUID sessionId = UUID.randomUUID();
    when(request.getCookies())
        .thenReturn(new Cookie[] {new Cookie("SHARED_SESSION_ID", sessionId.toString())});
    when(redisTemplate.opsForValue()).thenReturn(valueOperations);
    when(valueOperations.get(redisPrefix + sessionId)).thenReturn("invalid json");
    when(request.getSession(false)).thenReturn(null);

    filter.doFilterInternal(request, response, filterChain);

    verify(filterChain).doFilter(request, response);
  }

  @Test
  void doFilterInternal_validSessionId_successWithAllFields() throws Exception {
    UUID sessionId = UUID.randomUUID();
    when(request.getCookies())
        .thenReturn(new Cookie[] {new Cookie("SHARED_SESSION_ID", sessionId.toString())});
    when(redisTemplate.opsForValue()).thenReturn(valueOperations);
    String json =
        "{\"username\":\"testuser\",\"email\":\"test@example.com\",\"name\":\"Test User\",\"roles\":[\"USER\",\"ROLE_ADMIN\"],\"authenticated_at\":\"2023-10-01T12:00:00Z\"}";
    when(valueOperations.get(redisPrefix + sessionId)).thenReturn(json);

    filter.doFilterInternal(request, response, filterChain);

    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    assertNotNull(auth);
    assertEquals("testuser", auth.getName());
    assertEquals(3, auth.getAuthorities().size()); // ROLE_USER, ROLE_ADMIN, PASSWORD
    assertTrue(auth.getAuthorities().stream().anyMatch(a -> a.getAuthority().equals("ROLE_USER")));
    assertTrue(auth.getAuthorities().stream().anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN")));

    Map<String, Object> details = (Map<String, Object>) auth.getDetails();
    assertEquals("testuser", details.get("username"));
    assertEquals(sessionId.toString(), details.get("session_id"));
    assertEquals("test@example.com", details.get("email"));
    assertEquals("Test User", details.get("name"));
    assertEquals("2023-10-01T12:00:00Z", details.get("authenticated_at"));

    verify(filterChain).doFilter(request, response);
  }

  @Test
  void doFilterInternal_validSessionId_successWithMinimalFields() throws Exception {
    UUID sessionId = UUID.randomUUID();
    when(request.getCookies())
        .thenReturn(new Cookie[] {new Cookie("SHARED_SESSION_ID", sessionId.toString())});
    when(redisTemplate.opsForValue()).thenReturn(valueOperations);
    String json = "{\"username\":\"testuser\"}";
    when(valueOperations.get(redisPrefix + sessionId)).thenReturn(json);

    filter.doFilterInternal(request, response, filterChain);

    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    assertNotNull(auth);
    assertEquals("testuser", auth.getName());
    assertEquals(1, auth.getAuthorities().size()); // PASSWORD

    Map<String, Object> details = (Map<String, Object>) auth.getDetails();
    assertEquals("testuser", details.get("username"));
    assertNull(details.get("email"));
    assertNull(details.get("name"));
    assertNull(details.get("authenticated_at"));

    verify(filterChain).doFilter(request, response);
  }
}
