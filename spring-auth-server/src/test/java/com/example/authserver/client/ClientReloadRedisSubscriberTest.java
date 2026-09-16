package com.example.authserver.client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Collection;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.connection.Message;
import org.springframework.data.redis.connection.MessageListener;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.listener.RedisMessageListenerContainer;
import org.springframework.data.redis.listener.Topic;
import org.springframework.test.util.ReflectionTestUtils;

@ExtendWith(MockitoExtension.class)
class ClientReloadRedisSubscriberTest {

  @Mock private RedisConnectionFactory connectionFactory;

  @Mock private PostgresRegisteredClientRepository registeredClientRepository;

  private final ClientReloadRedisSubscriber subscriber = new ClientReloadRedisSubscriber();

  @SuppressWarnings("unchecked")
  private Map<MessageListener, ? extends Collection<Topic>> listenerTopics(
      RedisMessageListenerContainer container) {
    return (Map<MessageListener, ? extends Collection<Topic>>)
        ReflectionTestUtils.getField(container, "listenerTopics");
  }

  @Test
  void redisMessageListenerContainer_IsConfiguredWithConnectionFactoryAndListener() {
    RedisMessageListenerContainer container =
        subscriber.redisMessageListenerContainer(
            connectionFactory, registeredClientRepository, "oauth2as:clients:reload");

    assertNotNull(container);
    assertSame(connectionFactory, container.getConnectionFactory());
    assertFalse(listenerTopics(container).isEmpty());
  }

  @Test
  void registeredListener_TriggersRepositoryRefresh_OnReloadMessage() {
    RedisMessageListenerContainer container =
        subscriber.redisMessageListenerContainer(
            connectionFactory, registeredClientRepository, "oauth2as:clients:reload");

    MessageListener adapter = listenerTopics(container).keySet().iterator().next();

    Message message = mock(Message.class);
    when(message.getChannel()).thenReturn("oauth2as:clients:reload".getBytes());
    when(message.getBody()).thenReturn("reload".getBytes());

    adapter.onMessage(message, null);

    // The MessageListenerAdapter reflectively dispatches to our inline listener, which refreshes.
    verify(registeredClientRepository).refresh();
  }

  @Test
  void registeredListener_TopicMatchesConfiguredChannel() {
    String topicName = "custom:reload:channel";
    RedisMessageListenerContainer container =
        subscriber.redisMessageListenerContainer(
            connectionFactory, registeredClientRepository, topicName);

    Topic topic = listenerTopics(container).values().iterator().next().iterator().next();

    assertNotNull(topic);
    assertEquals(topicName, topic.getTopic());
  }
}
