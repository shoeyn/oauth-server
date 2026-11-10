package com.example.authserver;

import com.example.authserver.client.PostgresRegisteredClientRepository;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.listener.RedisMessageListenerContainer;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

@SpringBootTest
@TestPropertySource(
    properties = {
      "spring.autoconfigure.exclude=org.springframework.boot.autoconfigure.data.redis.RedisAutoConfiguration,org.springframework.boot.autoconfigure.data.redis.RedisReactiveAutoConfiguration,org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration,org.springframework.boot.autoconfigure.jdbc.JdbcTemplateAutoConfiguration",
      "spring.flyway.enabled=false",
      "aws.kms.enabled=false",
      "management.health.redis.enabled=false"
    })
class AuthServerApplicationTests {

  @MockitoBean private StringRedisTemplate stringRedisTemplate;
  @MockitoBean private LettuceConnectionFactory redisConnectionFactory;
  @MockitoBean private RedisMessageListenerContainer redisMessageListenerContainer;
  @MockitoBean private DataSource dataSource;
  @MockitoBean private JdbcTemplate jdbcTemplate;
  @MockitoBean private PostgresRegisteredClientRepository postgresRegisteredClientRepository;

  @Test
  void contextLoads() {}
}
