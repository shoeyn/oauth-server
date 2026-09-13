package com.example.authserver.controller;

import com.example.authserver.client.ClientConfigDto;
import com.example.authserver.client.PostgresRegisteredClientRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.security.PublicKey;
import java.time.Duration;
import java.util.List;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@ExtendWith(MockitoExtension.class)
public class ClientAdminControllerTest {

    private MockMvc mockMvc;

    @Mock
    private PostgresRegisteredClientRepository clientRepository;

    @Mock
    private StringRedisTemplate redisTemplate;

    @InjectMocks
    private ClientAdminController controller;

    private ObjectMapper objectMapper = new ObjectMapper();

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(controller, "adminApiKey", "secret-admin-key");
        ReflectionTestUtils.setField(controller, "reloadTopic", "auth_server:clients:reload");
        mockMvc = MockMvcBuilders.standaloneSetup(controller).build();
    }

    private RegisteredClient createClient(String clientId, String clientName, Boolean requirePar) {
        ClientSettings.Builder settingsBuilder = ClientSettings.builder()
                .requireProofKey(true)
                .requireAuthorizationConsent(true);
        if (requirePar != null) {
            settingsBuilder.setting("settings.client.require-pushed-authorization-requests", requirePar);
        }

        return RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(clientId)
                .clientName(clientName)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("http://localhost/callback")
                .postLogoutRedirectUri("http://localhost/logout")
                .scope("openid")
                .clientSettings(settingsBuilder.build())
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofMinutes(15))
                        .refreshTokenTimeToLive(Duration.ofDays(30))
                        .build())
                .build();
    }

    @Test
    void listClients_Unauthorized() throws Exception {
        mockMvc.perform(get("/api/admin/clients"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("Unauthorized"));

        mockMvc.perform(get("/api/admin/clients").header("X-Admin-Api-Key", ""))
                .andExpect(status().isUnauthorized());

        mockMvc.perform(get("/api/admin/clients").header("X-Admin-Api-Key", "wrong-key"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void listClients_Success() throws Exception {
        RegisteredClient client1 = createClient("client1", "Client One", true);
        
        RegisteredClient client2 = mock(RegisteredClient.class);
        when(client2.getId()).thenReturn("id2");
        when(client2.getClientId()).thenReturn("client2");
        when(client2.getClientName()).thenReturn(null);
        when(client2.getClientAuthenticationMethods()).thenReturn(java.util.Set.of(ClientAuthenticationMethod.CLIENT_SECRET_BASIC));
        when(client2.getAuthorizationGrantTypes()).thenReturn(java.util.Set.of(AuthorizationGrantType.AUTHORIZATION_CODE));
        when(client2.getRedirectUris()).thenReturn(java.util.Set.of("http://localhost/callback"));
        when(client2.getPostLogoutRedirectUris()).thenReturn(java.util.Set.of("http://localhost/logout"));
        when(client2.getScopes()).thenReturn(java.util.Set.of("openid"));
        when(client2.getClientSettings()).thenReturn(ClientSettings.builder().requireProofKey(true).requireAuthorizationConsent(true).build());
        when(client2.getTokenSettings()).thenReturn(TokenSettings.builder().accessTokenTimeToLive(Duration.ofMinutes(15)).refreshTokenTimeToLive(Duration.ofDays(30)).build());
        
        java.security.interfaces.RSAPublicKey mockPubKey = mock(java.security.interfaces.RSAPublicKey.class);
        when(mockPubKey.getEncoded()).thenReturn("dummy-key".getBytes());
        when(clientRepository.getClientPublicKey("client1")).thenReturn(mockPubKey);
        
        java.security.interfaces.RSAPublicKey errorPubKey = mock(java.security.interfaces.RSAPublicKey.class);
        when(errorPubKey.getEncoded()).thenThrow(new RuntimeException("key error"));
        when(clientRepository.getClientPublicKey("client2")).thenReturn(errorPubKey);

        when(clientRepository.findAll()).thenReturn(List.of(client1, client2));

        mockMvc.perform(get("/api/admin/clients").header("X-Admin-Api-Key", "secret-admin-key"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(2))
                .andExpect(jsonPath("$[0].clientId").value("client1"))
                .andExpect(jsonPath("$[0].clientName").value("Client One"))
                .andExpect(jsonPath("$[0].requirePushedAuthorizationRequests").value(true))
                .andExpect(jsonPath("$[0].publicKeyPem").isNotEmpty())
                .andExpect(jsonPath("$[1].clientId").value("client2"))
                .andExpect(jsonPath("$[1].clientName").value("client2"))
                .andExpect(jsonPath("$[1].requirePushedAuthorizationRequests").value(true)) // defaults to true
                .andExpect(jsonPath("$[1].publicKeyPem").value(""));
    }

    @Test
    void getClient_NotFound() throws Exception {
        when(clientRepository.findByClientId("unknown")).thenReturn(null);

        mockMvc.perform(get("/api/admin/clients/unknown").header("X-Admin-Api-Key", "secret-admin-key"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error").value("Client not found"));
    }

    @Test
    void getClient_Success() throws Exception {
        RegisteredClient client = createClient("client1", "Client One", false);
        when(clientRepository.findByClientId("client1")).thenReturn(client);
        when(clientRepository.getClientPublicKey("client1")).thenReturn(null); // test null key

        mockMvc.perform(get("/api/admin/clients/client1").header("X-Admin-Api-Key", "secret-admin-key"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.clientId").value("client1"))
                .andExpect(jsonPath("$.requirePushedAuthorizationRequests").value(false))
                .andExpect(jsonPath("$.publicKeyPem").value(""));
    }

    @Test
    void getClient_Unauthorized() throws Exception {
        mockMvc.perform(get("/api/admin/clients/client1"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void saveClient_Unauthorized() throws Exception {
        mockMvc.perform(post("/api/admin/clients")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void saveClient_MissingClientId() throws Exception {
        ClientConfigDto dto = new ClientConfigDto(null, null, null, null, null, null, null, null, null, null, null, null, null);
        mockMvc.perform(post("/api/admin/clients").header("X-Admin-Api-Key", "secret-admin-key")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(dto)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("clientId is required"));

        ClientConfigDto dto2 = new ClientConfigDto("   ", null, null, null, null, null, null, null, null, null, null, null, null);
        mockMvc.perform(post("/api/admin/clients").header("X-Admin-Api-Key", "secret-admin-key")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(dto2)))
                .andExpect(status().isBadRequest());
    }

    @Test
    void saveClient_Success() throws Exception {
        ClientConfigDto dto = new ClientConfigDto("new-client", null, null, null, null, null, null, null, null, null, null, null, null);
        
        mockMvc.perform(post("/api/admin/clients").header("X-Admin-Api-Key", "secret-admin-key")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(dto)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.status").value("created"))
                .andExpect(jsonPath("$.clientId").value("new-client"));

        verify(clientRepository).saveDtoToDatabase(any(ClientConfigDto.class));
        verify(clientRepository).reloadNearCacheFromDatabase();
        verify(redisTemplate).convertAndSend(eq("auth_server:clients:reload"), contains("new-client"));
    }

    @Test
    void saveClient_RedisException() throws Exception {
        ClientConfigDto dto = new ClientConfigDto("new-client", null, null, null, null, null, null, null, null, null, null, null, null);
        
        when(redisTemplate.convertAndSend(anyString(), anyString())).thenThrow(new RuntimeException("Redis down"));

        mockMvc.perform(post("/api/admin/clients").header("X-Admin-Api-Key", "secret-admin-key")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(dto)))
                .andExpect(status().isCreated());

        verify(clientRepository).saveDtoToDatabase(any(ClientConfigDto.class));
    }

    @Test
    void deleteClient_Unauthorized() throws Exception {
        mockMvc.perform(delete("/api/admin/clients/client1"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void deleteClient_Success() throws Exception {
        mockMvc.perform(delete("/api/admin/clients/client1").header("X-Admin-Api-Key", "secret-admin-key"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("deleted"))
                .andExpect(jsonPath("$.clientId").value("client1"));

        verify(clientRepository).deleteClient("client1");
        verify(redisTemplate).convertAndSend(eq("auth_server:clients:reload"), contains("client1"));
    }

    @Test
    void deleteClient_RedisException() throws Exception {
        when(redisTemplate.convertAndSend(anyString(), anyString())).thenThrow(new RuntimeException("Redis down"));

        mockMvc.perform(delete("/api/admin/clients/client1").header("X-Admin-Api-Key", "secret-admin-key"))
                .andExpect(status().isOk());

        verify(clientRepository).deleteClient("client1");
    }
}
