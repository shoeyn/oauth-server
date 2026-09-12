package com.example.authserver.client;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.MessageListener;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.listener.ChannelTopic;
import org.springframework.data.redis.listener.RedisMessageListenerContainer;
import org.springframework.data.redis.listener.adapter.MessageListenerAdapter;

@Slf4j
@Configuration(proxyBeanMethods = false)
public class ClientReloadRedisSubscriber {

    @Bean
    public RedisMessageListenerContainer redisMessageListenerContainer(
            RedisConnectionFactory connectionFactory,
            PostgresRegisteredClientRepository registeredClientRepository,
            @Value("${spring.data.redis.channel.reload:auth_server:clients:reload}") String reloadTopic) {

        RedisMessageListenerContainer container = new RedisMessageListenerContainer();
        container.setConnectionFactory(connectionFactory);

        MessageListenerAdapter adapter = new MessageListenerAdapter(
                (MessageListener) (message, pattern) -> {
                    String channel = new String(message.getChannel());
                    String body = new String(message.getBody());
                    log.info("Received Redis pub/sub reload signal on channel '{}': {}", channel, body);
                    registeredClientRepository.refresh();
                }
        );

        container.addMessageListener(adapter, new ChannelTopic(reloadTopic));
        log.info("Subscribed to Redis pub/sub channel '{}' for dynamic client re-registration", reloadTopic);
        return container;
    }
}
