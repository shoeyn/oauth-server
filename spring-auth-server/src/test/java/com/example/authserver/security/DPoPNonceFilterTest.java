package com.example.authserver.security;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.http.HttpHeaders;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.Method;
import java.time.Duration;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class DPoPNonceFilterTest {

    @Mock
    private StringRedisTemplate redisTemplate;

    @Mock
    private ValueOperations<String, String> valueOperations;

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @Mock
    private FilterChain filterChain;

    @InjectMocks
    private DPoPNonceFilter filter;

    @BeforeEach
    void setUp() {
        // leniency for redis ops mock
        lenient().when(redisTemplate.opsForValue()).thenReturn(valueOperations);
    }

    @Test
    void shouldNotFilter_ReturnsTrue_ForNonTokenPath() throws Exception {
        when(request.getRequestURI()).thenReturn("/api/data");

        Method method = DPoPNonceFilter.class.getDeclaredMethod("shouldNotFilter", HttpServletRequest.class);
        method.setAccessible(true);
        boolean result = (boolean) method.invoke(filter, request);

        assertTrue(result);
    }

    @Test
    void shouldNotFilter_ReturnsFalse_ForTokenPath() throws Exception {
        when(request.getRequestURI()).thenReturn("/oauth2/token");

        Method method = DPoPNonceFilter.class.getDeclaredMethod("shouldNotFilter", HttpServletRequest.class);
        method.setAccessible(true);
        boolean result = (boolean) method.invoke(filter, request);

        assertFalse(result);
    }

    @Test
    void doFilterInternal_PassesThrough_WhenBasicAuthHeaderPresent() throws ServletException, IOException {
        when(request.getRequestURI()).thenReturn("/oauth2/token");
        when(request.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn("Basic dXNlcjpwYXNz");

        filter.doFilter(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
        verifyNoInteractions(redisTemplate);
    }

    @Test
    void doFilterInternal_ChecksDPoP_WhenBearerAuthHeaderPresent() throws ServletException, IOException {
        when(request.getRequestURI()).thenReturn("/oauth2/token");
        when(request.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn("Bearer some-token");
        when(request.getParameter("client_secret")).thenReturn(null);
        when(request.getHeader("DPoP")).thenReturn(null);

        filter.doFilter(request, response, filterChain);
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void doFilterInternal_PassesThrough_WhenBasicAuthHeaderPresentDifferentCase() throws ServletException, IOException {
        when(request.getRequestURI()).thenReturn("/oauth2/token");
        when(request.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn("basic dXNlcjpwYXNz");

        filter.doFilter(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
        verifyNoInteractions(redisTemplate);
    }

    @Test
    void doFilterInternal_PassesThrough_WhenClientSecretParameterPresent() throws ServletException, IOException {
        when(request.getRequestURI()).thenReturn("/oauth2/token");
        when(request.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn(null);
        when(request.getParameter("client_secret")).thenReturn("my-secret");

        filter.doFilter(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
        verifyNoInteractions(redisTemplate);
    }

    @Test
    void doFilterInternal_PassesThrough_WhenNoDPoPHeader() throws ServletException, IOException {
        when(request.getRequestURI()).thenReturn("/oauth2/token");
        when(request.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn(null);
        when(request.getParameter("client_secret")).thenReturn(null);
        when(request.getHeader("DPoP")).thenReturn(null);

        filter.doFilter(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
        verifyNoInteractions(redisTemplate);
    }

    @Test
    void doFilterInternal_Rejects_WhenDPoPHeaderInvalid() throws ServletException, IOException {
        when(request.getRequestURI()).thenReturn("/oauth2/token");
        when(request.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn(null);
        when(request.getParameter("client_secret")).thenReturn(null);
        when(request.getHeader("DPoP")).thenReturn("invalid-jwt");
        
        StringWriter stringWriter = new StringWriter();
        when(response.getWriter()).thenReturn(new PrintWriter(stringWriter));

        filter.doFilter(request, response, filterChain);

        verify(response).setHeader(eq("DPoP-Nonce"), anyString());
        verify(response).setStatus(HttpServletResponse.SC_BAD_REQUEST);
        verify(response).setContentType("application/json");
        verify(redisTemplate.opsForValue()).set(anyString(), eq("1"), any(Duration.class));
        verify(filterChain, never()).doFilter(request, response);
        
        assertTrue(stringWriter.toString().contains("use_dpop_nonce"));
    }

    @Test
    void doFilterInternal_Rejects_WhenDPoPMissingNonceClaim() throws Exception {
        when(request.getRequestURI()).thenReturn("/oauth2/token");
        when(request.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn(null);
        when(request.getParameter("client_secret")).thenReturn(null);
        
        // Generate JWT without nonce
        JWSSigner signer = new MACSigner(new byte[32]);
        SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), new JWTClaimsSet.Builder().build());
        signedJWT.sign(signer);
        when(request.getHeader("DPoP")).thenReturn(signedJWT.serialize());
        
        StringWriter stringWriter = new StringWriter();
        when(response.getWriter()).thenReturn(new PrintWriter(stringWriter));

        filter.doFilter(request, response, filterChain);

        verify(response).setHeader(eq("DPoP-Nonce"), anyString());
        verify(response).setStatus(HttpServletResponse.SC_BAD_REQUEST);
        verify(filterChain, never()).doFilter(request, response);
    }

    @Test
    void doFilterInternal_Rejects_WhenNonceInvalidOrExpired() throws Exception {
        when(request.getRequestURI()).thenReturn("/oauth2/token");
        when(request.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn(null);
        when(request.getParameter("client_secret")).thenReturn(null);
        
        String nonce = "expired-nonce";
        JWSSigner signer = new MACSigner(new byte[32]);
        SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), new JWTClaimsSet.Builder().claim("nonce", nonce).build());
        signedJWT.sign(signer);
        when(request.getHeader("DPoP")).thenReturn(signedJWT.serialize());
        
        when(redisTemplate.delete("oauth2as:dpop_nonce:" + nonce)).thenReturn(false);
        
        StringWriter stringWriter = new StringWriter();
        when(response.getWriter()).thenReturn(new PrintWriter(stringWriter));

        filter.doFilter(request, response, filterChain);

        verify(response).setHeader(eq("DPoP-Nonce"), anyString());
        verify(response).setStatus(HttpServletResponse.SC_BAD_REQUEST);
        verify(filterChain, never()).doFilter(request, response);
    }

    @Test
    void doFilterInternal_Succeeds_WhenNonceValid() throws Exception {
        when(request.getRequestURI()).thenReturn("/oauth2/token");
        when(request.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn(null);
        when(request.getParameter("client_secret")).thenReturn(null);
        
        String nonce = "valid-nonce";
        JWSSigner signer = new MACSigner(new byte[32]);
        SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), new JWTClaimsSet.Builder().claim("nonce", nonce).build());
        signedJWT.sign(signer);
        when(request.getHeader("DPoP")).thenReturn(signedJWT.serialize());
        
        when(redisTemplate.delete("oauth2as:dpop_nonce:" + nonce)).thenReturn(true);

        filter.doFilter(request, response, filterChain);

        verify(response).setHeader(eq("DPoP-Nonce"), anyString());
        verify(redisTemplate.opsForValue()).set(anyString(), eq("1"), any(Duration.class));
        verify(filterChain).doFilter(request, response);
    }
}
