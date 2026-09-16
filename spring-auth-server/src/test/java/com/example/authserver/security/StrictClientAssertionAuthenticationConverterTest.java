package com.example.authserver.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.when;

import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;

@ExtendWith(MockitoExtension.class)
class StrictClientAssertionAuthenticationConverterTest {

  @Mock private HttpServletRequest request;

  private StrictClientAssertionAuthenticationConverter converter;

  @BeforeEach
  void setUp() {
    converter = new StrictClientAssertionAuthenticationConverter();
  }

  @Test
  void convert_RejectsBasicAuthorizationHeader_WithInvalidClient() {
    when(request.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn("Basic dXNlcjpwYXNz");

    OAuth2AuthenticationException ex =
        assertThrows(OAuth2AuthenticationException.class, () -> converter.convert(request));

    assertEquals(OAuth2ErrorCodes.INVALID_CLIENT, ex.getError().getErrorCode());
    assertTrue(ex.getError().getDescription().contains("client_secret_basic"));
  }

  @Test
  void convert_RejectsBasicAuthorizationHeaderCaseInsensitive() {
    when(request.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn("basic dXNlcjpwYXNz");

    OAuth2AuthenticationException ex =
        assertThrows(OAuth2AuthenticationException.class, () -> converter.convert(request));

    assertEquals(OAuth2ErrorCodes.INVALID_CLIENT, ex.getError().getErrorCode());
  }

  @Test
  void convert_RejectsClientSecretParameter_WithInvalidClient() {
    when(request.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn(null);
    when(request.getParameter("client_secret")).thenReturn("my-secret");

    OAuth2AuthenticationException ex =
        assertThrows(OAuth2AuthenticationException.class, () -> converter.convert(request));

    assertEquals(OAuth2ErrorCodes.INVALID_CLIENT, ex.getError().getErrorCode());
    assertTrue(ex.getError().getDescription().contains("client_secret_post"));
  }

  @Test
  void convert_DelegatesAndReturnsNull_WhenNoClientAssertionPresent() {
    // Neither basic auth header nor client_secret param nor a client_assertion present:
    // the underlying JwtClientAssertionAuthenticationConverter returns null.
    lenient().when(request.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn(null);
    lenient().when(request.getParameter("client_secret")).thenReturn(null);
    lenient().when(request.getParameter("client_assertion_type")).thenReturn(null);
    lenient().when(request.getParameter("client_assertion")).thenReturn(null);

    Authentication result = converter.convert(request);

    assertNull(result);
  }

  @Test
  void convert_DelegatesAndReturnsNull_WhenBearerAuthorizationHeaderPresent() {
    // A non-basic authorization scheme is not rejected outright; it is passed to the delegate,
    // which returns null in the absence of a client_assertion parameter.
    lenient().when(request.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn("Bearer sometoken");
    lenient().when(request.getParameter("client_secret")).thenReturn(null);

    Authentication result = converter.convert(request);

    assertNull(result);
  }
}
