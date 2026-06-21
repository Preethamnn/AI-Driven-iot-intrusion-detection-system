"""
Message bus integration for the AI-driven IoT IDS system.

This module provides integration with various message bus systems
including Kafka, NATS, and MQTT for high-volume data transport.
"""

import asyncio
import json
import uuid
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Dict, Any, List, Optional, Callable, AsyncIterator
from dataclasses import dataclass
from enum import Enum

from ..interfaces.secure_forwarder import SecureMessage, MessagePriority
from ..utils.logging_config import get_logger
from ..utils.error_handling import IDSError


class MessageBusType(str, Enum):
    """Enumeration of supported message bus types."""
    KAFKA = "kafka"
    NATS = "nats"
    MQTT = "mqtt"


@dataclass
class MessageBusConfig:
    """Configuration for message bus connection."""
    bus_type: MessageBusType
    connection_string: str
    topic_prefix: str = "ids"
    client_id: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    ssl_enabled: bool = False
    ssl_cert_path: Optional[str] = None
    ssl_key_path: Optional[str] = None
    ssl_ca_path: Optional[str] = None
    max_retries: int = 3
    retry_delay_seconds: int = 5
    batch_size: int = 100
    flush_timeout_seconds: int = 10


@dataclass
class MessageBusMessage:
    """Message for transport via message bus."""
    topic: str
    key: Optional[str]
    value: bytes
    headers: Dict[str, str]
    timestamp: datetime
    partition: Optional[int] = None


class MessageBusInterface(ABC):
    """Abstract interface for message bus implementations."""
    
    @abstractmethod
    async def connect(self) -> None:
        """Connect to the message bus."""
        pass
    
    @abstractmethod
    async def disconnect(self) -> None:
        """Disconnect from the message bus."""
        pass
    
    @abstractmethod
    async def publish(self, message: MessageBusMessage) -> bool:
        """Publish a message to the bus."""
        pass
    
    @abstractmethod
    async def publish_batch(self, messages: List[MessageBusMessage]) -> List[bool]:
        """Publish multiple messages in batch."""
        pass
    
    @abstractmethod
    async def subscribe(self, topic: str, 
                       callback: Callable[[MessageBusMessage], None]) -> None:
        """Subscribe to messages from a topic."""
        pass
    
    @abstractmethod
    async def unsubscribe(self, topic: str) -> None:
        """Unsubscribe from a topic."""
        pass
    
    @abstractmethod
    async def get_health_status(self) -> Dict[str, Any]:
        """Get health status of the message bus connection."""
        pass


class KafkaMessageBus(MessageBusInterface):
    """Kafka message bus implementation."""
    
    def __init__(self, config: MessageBusConfig):
        self.config = config
        self.logger = get_logger(__name__)
        self._producer = None
        self._consumer = None
        self._connected = False
        
        # Import kafka-python only when needed
        try:
            from kafka import KafkaProducer, KafkaConsumer
            from kafka.errors import KafkaError
            self._KafkaProducer = KafkaProducer
            self._KafkaConsumer = KafkaConsumer
            self._KafkaError = KafkaError
        except ImportError:
            raise IDSError("kafka-python package is required for Kafka integration")
    
    async def connect(self) -> None:
        """Connect to Kafka."""
        try:
            # Parse connection string (bootstrap_servers)
            bootstrap_servers = self.config.connection_string.split(',')
            
            # Configure SSL if enabled
            ssl_config = {}
            if self.config.ssl_enabled:
                ssl_config = {
                    'security_protocol': 'SSL',
                    'ssl_check_hostname': True,
                    'ssl_cafile': self.config.ssl_ca_path,
                    'ssl_certfile': self.config.ssl_cert_path,
                    'ssl_keyfile': self.config.ssl_key_path,
                }
            
            # Create producer
            self._producer = self._KafkaProducer(
                bootstrap_servers=bootstrap_servers,
                client_id=self.config.client_id or f"ids-producer-{uuid.uuid4().hex[:8]}",
                value_serializer=lambda v: v if isinstance(v, bytes) else v.encode('utf-8'),
                key_serializer=lambda k: k.encode('utf-8') if k else None,
                retries=self.config.max_retries,
                batch_size=self.config.batch_size * 1024,  # Convert to bytes
                linger_ms=self.config.flush_timeout_seconds * 1000,
                **ssl_config
            )
            
            self._connected = True
            self.logger.info(f"Connected to Kafka: {bootstrap_servers}")
            
        except Exception as e:
            self.logger.error(f"Failed to connect to Kafka: {e}")
            raise IDSError(f"Kafka connection failed: {e}")
    
    async def disconnect(self) -> None:
        """Disconnect from Kafka."""
        try:
            if self._producer:
                self._producer.close()
                self._producer = None
            
            if self._consumer:
                self._consumer.close()
                self._consumer = None
            
            self._connected = False
            self.logger.info("Disconnected from Kafka")
            
        except Exception as e:
            self.logger.error(f"Error disconnecting from Kafka: {e}")
    
    async def publish(self, message: MessageBusMessage) -> bool:
        """Publish a message to Kafka."""
        if not self._connected or not self._producer:
            raise IDSError("Not connected to Kafka")
        
        try:
            future = self._producer.send(
                topic=message.topic,
                key=message.key,
                value=message.value,
                headers=[(k, v.encode('utf-8')) for k, v in message.headers.items()],
                partition=message.partition,
                timestamp_ms=int(message.timestamp.timestamp() * 1000)
            )
            
            # Wait for delivery confirmation
            record_metadata = future.get(timeout=10)
            
            self.logger.debug(
                f"Message published to Kafka: topic={record_metadata.topic}, "
                f"partition={record_metadata.partition}, offset={record_metadata.offset}"
            )
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to publish message to Kafka: {e}")
            return False
    
    async def publish_batch(self, messages: List[MessageBusMessage]) -> List[bool]:
        """Publish multiple messages to Kafka in batch."""
        results = []
        
        for message in messages:
            result = await self.publish(message)
            results.append(result)
        
        # Flush producer to ensure all messages are sent
        if self._producer:
            self._producer.flush()
        
        return results
    
    async def subscribe(self, topic: str, 
                       callback: Callable[[MessageBusMessage], None]) -> None:
        """Subscribe to Kafka topic."""
        # Note: This is a simplified implementation
        # In production, you'd want to run this in a separate task/thread
        try:
            bootstrap_servers = self.config.connection_string.split(',')
            
            ssl_config = {}
            if self.config.ssl_enabled:
                ssl_config = {
                    'security_protocol': 'SSL',
                    'ssl_check_hostname': True,
                    'ssl_cafile': self.config.ssl_ca_path,
                    'ssl_certfile': self.config.ssl_cert_path,
                    'ssl_keyfile': self.config.ssl_key_path,
                }
            
            self._consumer = self._KafkaConsumer(
                topic,
                bootstrap_servers=bootstrap_servers,
                client_id=self.config.client_id or f"ids-consumer-{uuid.uuid4().hex[:8]}",
                group_id=f"{self.config.topic_prefix}-consumer-group",
                auto_offset_reset='latest',
                value_deserializer=lambda m: m,
                key_deserializer=lambda m: m.decode('utf-8') if m else None,
                **ssl_config
            )
            
            # Start consuming in background task
            asyncio.create_task(self._consume_messages(callback))
            
            self.logger.info(f"Subscribed to Kafka topic: {topic}")
            
        except Exception as e:
            self.logger.error(f"Failed to subscribe to Kafka topic {topic}: {e}")
            raise IDSError(f"Kafka subscription failed: {e}")
    
    async def unsubscribe(self, topic: str) -> None:
        """Unsubscribe from Kafka topic."""
        if self._consumer:
            self._consumer.unsubscribe()
            self.logger.info(f"Unsubscribed from Kafka topic: {topic}")
    
    async def get_health_status(self) -> Dict[str, Any]:
        """Get Kafka connection health status."""
        return {
            "connected": self._connected,
            "producer_ready": self._producer is not None,
            "consumer_ready": self._consumer is not None,
            "bootstrap_servers": self.config.connection_string
        }
    
    async def _consume_messages(self, callback: Callable[[MessageBusMessage], None]) -> None:
        """Background task to consume messages."""
        try:
            for message in self._consumer:
                bus_message = MessageBusMessage(
                    topic=message.topic,
                    key=message.key,
                    value=message.value,
                    headers={k: v.decode('utf-8') for k, v in message.headers},
                    timestamp=datetime.fromtimestamp(message.timestamp / 1000),
                    partition=message.partition
                )
                
                try:
                    callback(bus_message)
                except Exception as e:
                    self.logger.error(f"Error in message callback: {e}")
                    
        except Exception as e:
            self.logger.error(f"Error consuming Kafka messages: {e}")


class NATSMessageBus(MessageBusInterface):
    """NATS message bus implementation."""
    
    def __init__(self, config: MessageBusConfig):
        self.config = config
        self.logger = get_logger(__name__)
        self._client = None
        self._connected = False
        self._subscriptions = {}
        
        # Import nats only when needed
        try:
            import nats
            self._nats = nats
        except ImportError:
            raise IDSError("nats-py package is required for NATS integration")
    
    async def connect(self) -> None:
        """Connect to NATS."""
        try:
            # Parse connection options
            options = {
                "servers": [self.config.connection_string],
                "name": self.config.client_id or f"ids-client-{uuid.uuid4().hex[:8]}",
                "max_reconnect_attempts": self.config.max_retries,
                "reconnect_time_wait": self.config.retry_delay_seconds,
            }
            
            # Add authentication if provided
            if self.config.username and self.config.password:
                options["user"] = self.config.username
                options["password"] = self.config.password
            
            # Add TLS if enabled
            if self.config.ssl_enabled:
                import ssl
                ssl_context = ssl.create_default_context()
                if self.config.ssl_ca_path:
                    ssl_context.load_verify_locations(self.config.ssl_ca_path)
                if self.config.ssl_cert_path and self.config.ssl_key_path:
                    ssl_context.load_cert_chain(self.config.ssl_cert_path, self.config.ssl_key_path)
                options["tls"] = ssl_context
            
            self._client = await self._nats.connect(**options)
            self._connected = True
            
            self.logger.info(f"Connected to NATS: {self.config.connection_string}")
            
        except Exception as e:
            self.logger.error(f"Failed to connect to NATS: {e}")
            raise IDSError(f"NATS connection failed: {e}")
    
    async def disconnect(self) -> None:
        """Disconnect from NATS."""
        try:
            if self._client:
                await self._client.close()
                self._client = None
            
            self._connected = False
            self._subscriptions.clear()
            self.logger.info("Disconnected from NATS")
            
        except Exception as e:
            self.logger.error(f"Error disconnecting from NATS: {e}")
    
    async def publish(self, message: MessageBusMessage) -> bool:
        """Publish a message to NATS."""
        if not self._connected or not self._client:
            raise IDSError("Not connected to NATS")
        
        try:
            # NATS doesn't support headers in the same way, so we embed them in the payload
            payload = {
                "headers": message.headers,
                "data": message.value.decode('utf-8') if isinstance(message.value, bytes) else message.value,
                "timestamp": message.timestamp.isoformat()
            }
            
            await self._client.publish(
                subject=message.topic,
                payload=json.dumps(payload).encode('utf-8')
            )
            
            self.logger.debug(f"Message published to NATS: subject={message.topic}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to publish message to NATS: {e}")
            return False
    
    async def publish_batch(self, messages: List[MessageBusMessage]) -> List[bool]:
        """Publish multiple messages to NATS."""
        results = []
        
        for message in messages:
            result = await self.publish(message)
            results.append(result)
        
        return results
    
    async def subscribe(self, topic: str, 
                       callback: Callable[[MessageBusMessage], None]) -> None:
        """Subscribe to NATS subject."""
        if not self._connected or not self._client:
            raise IDSError("Not connected to NATS")
        
        try:
            async def message_handler(msg):
                try:
                    # Parse the embedded payload
                    payload = json.loads(msg.data.decode('utf-8'))
                    
                    bus_message = MessageBusMessage(
                        topic=msg.subject,
                        key=None,  # NATS doesn't have keys
                        value=payload["data"].encode('utf-8'),
                        headers=payload.get("headers", {}),
                        timestamp=datetime.fromisoformat(payload["timestamp"])
                    )
                    
                    callback(bus_message)
                    
                except Exception as e:
                    self.logger.error(f"Error processing NATS message: {e}")
            
            subscription = await self._client.subscribe(topic, cb=message_handler)
            self._subscriptions[topic] = subscription
            
            self.logger.info(f"Subscribed to NATS subject: {topic}")
            
        except Exception as e:
            self.logger.error(f"Failed to subscribe to NATS subject {topic}: {e}")
            raise IDSError(f"NATS subscription failed: {e}")
    
    async def unsubscribe(self, topic: str) -> None:
        """Unsubscribe from NATS subject."""
        if topic in self._subscriptions:
            await self._subscriptions[topic].unsubscribe()
            del self._subscriptions[topic]
            self.logger.info(f"Unsubscribed from NATS subject: {topic}")
    
    async def get_health_status(self) -> Dict[str, Any]:
        """Get NATS connection health status."""
        return {
            "connected": self._connected,
            "client_ready": self._client is not None,
            "active_subscriptions": len(self._subscriptions),
            "server": self.config.connection_string
        }


class MQTTMessageBus(MessageBusInterface):
    """MQTT message bus implementation."""
    
    def __init__(self, config: MessageBusConfig):
        self.config = config
        self.logger = get_logger(__name__)
        self._client = None
        self._connected = False
        self._callbacks = {}
        
        # Import paho-mqtt only when needed
        try:
            import asyncio_mqtt
            self._asyncio_mqtt = asyncio_mqtt
        except ImportError:
            raise IDSError("asyncio-mqtt package is required for MQTT integration")
    
    async def connect(self) -> None:
        """Connect to MQTT broker."""
        try:
            # Parse connection string (host:port)
            if ':' in self.config.connection_string:
                host, port = self.config.connection_string.split(':', 1)
                port = int(port)
            else:
                host = self.config.connection_string
                port = 1883 if not self.config.ssl_enabled else 8883
            
            # Configure client options
            client_options = {
                "hostname": host,
                "port": port,
                "client_id": self.config.client_id or f"ids-mqtt-{uuid.uuid4().hex[:8]}",
                "keepalive": 60,
                "will": None
            }
            
            # Add authentication if provided
            if self.config.username and self.config.password:
                client_options["username"] = self.config.username
                client_options["password"] = self.config.password
            
            # Add TLS if enabled
            if self.config.ssl_enabled:
                import ssl
                ssl_context = ssl.create_default_context()
                if self.config.ssl_ca_path:
                    ssl_context.load_verify_locations(self.config.ssl_ca_path)
                if self.config.ssl_cert_path and self.config.ssl_key_path:
                    ssl_context.load_cert_chain(self.config.ssl_cert_path, self.config.ssl_key_path)
                client_options["tls_context"] = ssl_context
            
            self._client = self._asyncio_mqtt.Client(**client_options)
            await self._client.__aenter__()
            
            self._connected = True
            self.logger.info(f"Connected to MQTT broker: {host}:{port}")
            
        except Exception as e:
            self.logger.error(f"Failed to connect to MQTT: {e}")
            raise IDSError(f"MQTT connection failed: {e}")
    
    async def disconnect(self) -> None:
        """Disconnect from MQTT broker."""
        try:
            if self._client:
                await self._client.__aexit__(None, None, None)
                self._client = None
            
            self._connected = False
            self._callbacks.clear()
            self.logger.info("Disconnected from MQTT")
            
        except Exception as e:
            self.logger.error(f"Error disconnecting from MQTT: {e}")
    
    async def publish(self, message: MessageBusMessage) -> bool:
        """Publish a message to MQTT."""
        if not self._connected or not self._client:
            raise IDSError("Not connected to MQTT")
        
        try:
            # MQTT payload with headers embedded
            payload = {
                "headers": message.headers,
                "data": message.value.decode('utf-8') if isinstance(message.value, bytes) else message.value,
                "timestamp": message.timestamp.isoformat()
            }
            
            await self._client.publish(
                topic=message.topic,
                payload=json.dumps(payload),
                qos=1,  # At least once delivery
                retain=False
            )
            
            self.logger.debug(f"Message published to MQTT: topic={message.topic}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to publish message to MQTT: {e}")
            return False
    
    async def publish_batch(self, messages: List[MessageBusMessage]) -> List[bool]:
        """Publish multiple messages to MQTT."""
        results = []
        
        for message in messages:
            result = await self.publish(message)
            results.append(result)
        
        return results
    
    async def subscribe(self, topic: str, 
                       callback: Callable[[MessageBusMessage], None]) -> None:
        """Subscribe to MQTT topic."""
        if not self._connected or not self._client:
            raise IDSError("Not connected to MQTT")
        
        try:
            await self._client.subscribe(topic, qos=1)
            self._callbacks[topic] = callback
            
            # Start message processing task
            asyncio.create_task(self._process_messages())
            
            self.logger.info(f"Subscribed to MQTT topic: {topic}")
            
        except Exception as e:
            self.logger.error(f"Failed to subscribe to MQTT topic {topic}: {e}")
            raise IDSError(f"MQTT subscription failed: {e}")
    
    async def unsubscribe(self, topic: str) -> None:
        """Unsubscribe from MQTT topic."""
        if self._client and topic in self._callbacks:
            await self._client.unsubscribe(topic)
            del self._callbacks[topic]
            self.logger.info(f"Unsubscribed from MQTT topic: {topic}")
    
    async def get_health_status(self) -> Dict[str, Any]:
        """Get MQTT connection health status."""
        return {
            "connected": self._connected,
            "client_ready": self._client is not None,
            "active_subscriptions": len(self._callbacks),
            "broker": self.config.connection_string
        }
    
    async def _process_messages(self) -> None:
        """Background task to process MQTT messages."""
        try:
            async for message in self._client.messages:
                topic = message.topic.value
                
                if topic in self._callbacks:
                    try:
                        # Parse the embedded payload
                        payload = json.loads(message.payload.decode('utf-8'))
                        
                        bus_message = MessageBusMessage(
                            topic=topic,
                            key=None,  # MQTT doesn't have keys
                            value=payload["data"].encode('utf-8'),
                            headers=payload.get("headers", {}),
                            timestamp=datetime.fromisoformat(payload["timestamp"])
                        )
                        
                        self._callbacks[topic](bus_message)
                        
                    except Exception as e:
                        self.logger.error(f"Error processing MQTT message: {e}")
                        
        except Exception as e:
            self.logger.error(f"Error in MQTT message processing: {e}")


class MessageBusManager:
    """Manager for message bus integrations."""
    
    def __init__(self):
        self.logger = get_logger(__name__)
        self._buses: Dict[str, MessageBusInterface] = {}
    
    async def add_bus(self, name: str, config: MessageBusConfig) -> None:
        """Add a message bus configuration."""
        try:
            if config.bus_type == MessageBusType.KAFKA:
                bus = KafkaMessageBus(config)
            elif config.bus_type == MessageBusType.NATS:
                bus = NATSMessageBus(config)
            elif config.bus_type == MessageBusType.MQTT:
                bus = MQTTMessageBus(config)
            else:
                raise ValueError(f"Unsupported message bus type: {config.bus_type}")
            
            await bus.connect()
            self._buses[name] = bus
            
            self.logger.info(f"Added message bus '{name}' of type {config.bus_type}")
            
        except Exception as e:
            self.logger.error(f"Failed to add message bus '{name}': {e}")
            raise IDSError(f"Failed to add message bus: {e}")
    
    async def remove_bus(self, name: str) -> None:
        """Remove a message bus."""
        if name in self._buses:
            await self._buses[name].disconnect()
            del self._buses[name]
            self.logger.info(f"Removed message bus '{name}'")
    
    def get_bus(self, name: str) -> Optional[MessageBusInterface]:
        """Get a message bus by name."""
        return self._buses.get(name)
    
    async def publish_to_all(self, message: MessageBusMessage) -> Dict[str, bool]:
        """Publish a message to all configured buses."""
        results = {}
        
        for name, bus in self._buses.items():
            try:
                result = await bus.publish(message)
                results[name] = result
            except Exception as e:
                self.logger.error(f"Failed to publish to bus '{name}': {e}")
                results[name] = False
        
        return results
    
    async def get_all_health_status(self) -> Dict[str, Dict[str, Any]]:
        """Get health status of all message buses."""
        status = {}
        
        for name, bus in self._buses.items():
            try:
                status[name] = await bus.get_health_status()
            except Exception as e:
                status[name] = {"error": str(e)}
        
        return status
    
    async def disconnect_all(self) -> None:
        """Disconnect from all message buses."""
        for name, bus in self._buses.items():
            try:
                await bus.disconnect()
            except Exception as e:
                self.logger.error(f"Error disconnecting from bus '{name}': {e}")
        
        self._buses.clear()
        self.logger.info("Disconnected from all message buses")
    
    def convert_secure_message_to_bus_message(self, 
                                            secure_msg: SecureMessage,
                                            topic: str) -> MessageBusMessage:
        """Convert a SecureMessage to MessageBusMessage format."""
        return MessageBusMessage(
            topic=topic,
            key=secure_msg.message_id,
            value=json.dumps(secure_msg.to_dict()).encode('utf-8'),
            headers={
                "message_type": secure_msg.message_type,
                "source_component": secure_msg.source_component,
                "destination_component": secure_msg.destination_component,
                "priority": secure_msg.priority.value
            },
            timestamp=secure_msg.timestamp
        )