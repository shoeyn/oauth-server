package com.example.authserver.config;

import com.example.authserver.security.SharedRedisSessionFilter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutFilter;

@Configuration
@EnableWebSecurity
public class DefaultSecurityConfig {

    @Value("${auth.rails.login-url:http://localhost:3000/login}")
    private String railsLoginUrl;

    @Value("${auth.server.issuer-url:http://localhost:9000}")
    private String issuerUrl;

    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(
            HttpSecurity http,
            StringRedisTemplate redisTemplate) throws Exception {

        http
            .headers(Customizer.withDefaults())
            .csrf(csrf -> csrf.ignoringRequestMatchers("/api/admin/**", "/actuator/**"))
            .authorizeHttpRequests((authorize) -> authorize
                .requestMatchers("/actuator/**", "/error", "/health", "/.well-known/**", "/api/admin/**").permitAll()
                .anyRequest().authenticated()
            )
            // Security Improvement: Disable built-in Spring Security form login and basic auth
            // All user authentication must exclusively route through the external Rails login application
            .formLogin(form -> form.disable())
            .httpBasic(basic -> basic.disable())
            .exceptionHandling((exceptions) -> exceptions
                .authenticationEntryPoint(new ExternalLoginAuthenticationEntryPoint(railsLoginUrl, issuerUrl))
            )
            .addFilterAfter(
                new SharedRedisSessionFilter(redisTemplate),
                LogoutFilter.class
            );

        return http.build();
    }
}
