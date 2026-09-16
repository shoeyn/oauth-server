package com.example.authserver.security;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.Method;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;

@ExtendWith(MockitoExtension.class)
class AdminApiKeyFilterTest {

  @Mock private HttpServletRequest request;

  @Mock private HttpServletResponse response;

  @Mock private FilterChain filterChain;

  private boolean shouldNotFilter(AdminApiKeyFilter filter, HttpServletRequest req)
      throws Exception {
    Method method =
        AdminApiKeyFilter.class.getDeclaredMethod("shouldNotFilter", HttpServletRequest.class);
    method.setAccessible(true);
    return (boolean) method.invoke(filter, req);
  }

  @Test
  void shouldNotFilter_ReturnsTrue_ForNonAdminPath() throws Exception {
    AdminApiKeyFilter filter = new AdminApiKeyFilter("secret");
    when(request.getRequestURI()).thenReturn("/oauth2/token");

    assertTrue(shouldNotFilter(filter, request));
  }

  @Test
  void shouldNotFilter_ReturnsFalse_ForAdminPath() throws Exception {
    AdminApiKeyFilter filter = new AdminApiKeyFilter("secret");
    when(request.getRequestURI()).thenReturn("/api/admin/clients");

    assertFalse(shouldNotFilter(filter, request));
  }

  @Test
  void doFilter_PassesThrough_WhenApiKeyMatches() throws Exception {
    AdminApiKeyFilter filter = new AdminApiKeyFilter("secret-key");
    when(request.getRequestURI()).thenReturn("/api/admin/clients");
    when(request.getHeader("X-Admin-Api-Key")).thenReturn("secret-key");

    filter.doFilter(request, response, filterChain);

    verify(filterChain).doFilter(request, response);
    verify(response, never()).setStatus(HttpStatus.UNAUTHORIZED.value());
  }

  @Test
  void doFilter_Rejects_WhenApiKeyMissing() throws Exception {
    AdminApiKeyFilter filter = new AdminApiKeyFilter("secret-key");
    when(request.getRequestURI()).thenReturn("/api/admin/clients");
    when(request.getHeader("X-Admin-Api-Key")).thenReturn(null);
    StringWriter writer = new StringWriter();
    when(response.getWriter()).thenReturn(new PrintWriter(writer));

    filter.doFilter(request, response, filterChain);

    verify(response).setStatus(HttpStatus.UNAUTHORIZED.value());
    verify(response).setContentType(MediaType.APPLICATION_JSON_VALUE);
    verify(filterChain, never()).doFilter(request, response);
    assertTrue(writer.toString().contains("Unauthorized"));
  }

  @Test
  void doFilter_Rejects_WhenApiKeyMismatch() throws Exception {
    AdminApiKeyFilter filter = new AdminApiKeyFilter("secret-key");
    when(request.getRequestURI()).thenReturn("/api/admin/users");
    when(request.getHeader("X-Admin-Api-Key")).thenReturn("wrong-key");
    StringWriter writer = new StringWriter();
    when(response.getWriter()).thenReturn(new PrintWriter(writer));

    filter.doFilter(request, response, filterChain);

    verify(response).setStatus(HttpStatus.UNAUTHORIZED.value());
    verify(filterChain, never()).doFilter(request, response);
  }

  @Test
  void doFilter_Rejects_WhenExpectedKeyNull_AndProvidedKeyPresent() throws Exception {
    AdminApiKeyFilter filter = new AdminApiKeyFilter(null);
    when(request.getRequestURI()).thenReturn("/api/admin/clients");
    when(request.getHeader("X-Admin-Api-Key")).thenReturn("anything");
    StringWriter writer = new StringWriter();
    when(response.getWriter()).thenReturn(new PrintWriter(writer));

    filter.doFilter(request, response, filterChain);

    verify(response).setStatus(HttpStatus.UNAUTHORIZED.value());
    verify(filterChain, never()).doFilter(request, response);
  }

  @Test
  void doFilter_SkipsEntirely_ForNonAdminPath() throws Exception {
    AdminApiKeyFilter filter = new AdminApiKeyFilter("secret-key");
    when(request.getRequestURI()).thenReturn("/public/resource");

    filter.doFilter(request, response, filterChain);

    verify(filterChain).doFilter(request, response);
    verifyNoInteractions(response);
  }
}
