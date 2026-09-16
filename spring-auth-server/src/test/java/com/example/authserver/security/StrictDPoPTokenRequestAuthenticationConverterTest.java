package com.example.authserver.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;

import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;

@ExtendWith(MockitoExtension.class)
class StrictDPoPTokenRequestAuthenticationConverterTest {

  @Mock private HttpServletRequest request;

  private StrictDPoPTokenRequestAuthenticationConverter converter;

  @BeforeEach
  void setUp() {
    converter = new StrictDPoPTokenRequestAuthenticationConverter();
  }

  @Test
  void convert_Rejects_WhenGrantTypePresentButDPoPMissing() {
    when(request.getParameter(OAuth2ParameterNames.GRANT_TYPE)).thenReturn("authorization_code");
    when(request.getHeader("DPoP")).thenReturn(null);

    OAuth2AuthenticationException ex =
        assertThrows(OAuth2AuthenticationException.class, () -> converter.convert(request));

    assertEquals("invalid_dpop_proof", ex.getError().getErrorCode());
  }

  @Test
  void convert_Rejects_WhenGrantTypePresentButDPoPBlank() {
    when(request.getParameter(OAuth2ParameterNames.GRANT_TYPE)).thenReturn("refresh_token");
    when(request.getHeader("DPoP")).thenReturn("   ");

    assertThrows(OAuth2AuthenticationException.class, () -> converter.convert(request));
  }

  @Test
  void convert_ReturnsNull_WhenGrantTypeAndDPoPBothPresent() {
    when(request.getParameter(OAuth2ParameterNames.GRANT_TYPE)).thenReturn("authorization_code");
    when(request.getHeader("DPoP")).thenReturn("eyJ0eXAiOiJkcG9wK2p3dCJ9.payload.sig");

    Authentication result = converter.convert(request);

    assertNull(result);
  }

  @Test
  void convert_ReturnsNull_WhenNoGrantType() {
    when(request.getParameter(OAuth2ParameterNames.GRANT_TYPE)).thenReturn(null);
    when(request.getHeader("DPoP")).thenReturn(null);

    Authentication result = converter.convert(request);

    assertNull(result);
  }
}
