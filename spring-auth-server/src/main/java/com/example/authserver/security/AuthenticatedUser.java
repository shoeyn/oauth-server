package com.example.authserver.security;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.io.Serializable;
import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
public record AuthenticatedUser(
        @JsonProperty("username") String username,
        @JsonProperty("email") String email,
        @JsonProperty("name") String name,
        @JsonProperty("roles") List<String> roles,
        @JsonProperty("authenticated_at") String authenticatedAt
) implements Serializable {

    public List<String> roles() {
        return roles != null ? roles : List.of();
    }
}
