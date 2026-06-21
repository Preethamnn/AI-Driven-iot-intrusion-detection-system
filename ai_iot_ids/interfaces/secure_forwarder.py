"""
Secure Forwarder interface for the AI-driven IoT IDS system.

This module defines the abstract interface for secure data transport
components that handle encrypted communication between system components
using mTLS and message bus integration.
"""

from abc import abstractmethod
from typing import Dict, Any, List, Optional, AsyncIterator
from dataclasses import dataclass
from datetime import datetime
from enum import Enum

from .base import BaseInterface


class TransportProtocol(str, Enum):
    """Enumeration of supported transport protocols."""
    HTTPS = "https"
    KAFKA = "kafka"
    NATS = "nats"
    MQTT = "mqtt"


class MessagePriority(str, Enum):
    """Enumeration of message priority levels."""
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class SecureMessage:
    """Secure message for transport between components."""
    message_id: str
    timestamp: datetime
    source_component: str
    destination_component: str
    message_type: str
    payload: Dict[str, Any]
    priority: MessagePriority = MessagePriority.NORMAL
    retry_count: int = 0
    max_retries: int = 3
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert message to dictionary for serialization."""
        return {
            "message_id": self.message_id,
            "timestamp": self.timestamp.isoformat(),
            "source_component": self.source_component,
            "destination_component": self.destination_component,
            "message_type": self.message_type,
            "payload": self.payload,
            "priority": self.priority.value,
            "retry_count": self.retry_count,
            "max_retries": self.max_retries
        }


@dataclass
class TransportEndpoint:
    """Transport endpoint configuration."""
    url: str
    protocol: TransportProtocol
    authentication: Dict[str, str]
    timeout_seconds: int = 30
    max_connections: int = 10
    
    def is_secure(self) -> bool:
        """Check if endpoint uses secure transport."""
        return (self.url.startswith('https://') or 
                'ssl' in self.authentication or 
                'tls' in self.authentication)


@dataclass
class DeliveryReceipt:
    """Receipt confirming message delivery."""
    message_id: str
    delivered_at: datetime
    endpoint: str
    status: str
    error_message: Optional[str] = None


class SecureForwarderInterface(BaseInterface):
    """
    Abstract interface for secure data forwarding components.
    
    Implementations should handle encrypted data transport using
    mTLS, message bus integration, retry mechanisms, and
    backpressure management for reliable data delivery.
    """
    
    @abstractmethod
    async def send_message(self, message: SecureMessage, 
                          endpoint: TransportEndpoint) -> DeliveryReceipt:
        """
        Send a secure message to the specified endpoint.
        
        Args:
            message: Secure message to send
            endpoint: Destination endpoint configuration
            
        Returns:
            DeliveryReceipt confirming delivery status
            
        Raises:
            ConnectionError: If endpoint is unreachable
            AuthenticationError: If authentication fails
            TimeoutError: If delivery times out
        """
        pass
    
    @abstractmethod
    async def send_batch(self, messages: List[SecureMessage], 
                        endpoint: TransportEndpoint) -> List[DeliveryReceipt]:
        """
        Send multiple messages in batch for improved performance.
        
        Args:
            messages: List of messages to send
            endpoint: Destination endpoint configuration
            
        Returns:
            List of delivery receipts (one per message)
        """
        pass
    
    @abstractmethod
    async def setup_mtls(self, cert_path: str, key_path: str, 
                        ca_path: str) -> None:
        """
        Configure mutual TLS authentication.
        
        Args:
            cert_path: Path to client certificate file
            key_path: Path to client private key file
            ca_path: Path to certificate authority file
            
        Raises:
            FileNotFoundError: If certificate files are missing
            ValueError: If certificates are invalid
        """
        pass
    
    @abstractmethod
    async def rotate_certificates(self) -> None:
        """
        Rotate TLS certificates for enhanced security.
        
        Should handle certificate renewal without service interruption.
        """
        pass
    
    @abstractmethod
    async def configure_retry_policy(self, max_retries: int, 
                                   backoff_multiplier: float,
                                   max_backoff_seconds: int) -> None:
        """
        Configure retry policy for failed message deliveries.
        
        Args:
            max_retries: Maximum number of retry attempts
            backoff_multiplier: Exponential backoff multiplier
            max_backoff_seconds: Maximum backoff delay
        """
        pass
    
    @abstractmethod
    async def enable_local_buffering(self, buffer_size_mb: int, 
                                   persistence_path: str) -> None:
        """
        Enable local buffering for offline operation.
        
        Args:
            buffer_size_mb: Maximum buffer size in megabytes
            persistence_path: Path for persistent buffer storage
        """
        pass
    
    @abstractmethod
    async def get_buffer_status(self) -> Dict[str, Any]:
        """
        Get current buffer status and utilization.
        
        Returns:
            Dictionary containing:
            - buffer_size_mb: Current buffer size
            - buffer_utilization: Percentage of buffer used
            - queued_messages: Number of queued messages
            - oldest_message_age_seconds: Age of oldest queued message
        """
        pass
    
    @abstractmethod
    async def flush_buffer(self) -> int:
        """
        Flush all buffered messages to their destinations.
        
        Returns:
            Number of messages successfully delivered
        """
        pass
    
    @abstractmethod
    async def register_endpoint(self, name: str, 
                              endpoint: TransportEndpoint) -> None:
        """
        Register a named endpoint for message routing.
        
        Args:
            name: Logical name for the endpoint
            endpoint: Endpoint configuration
        """
        pass
    
    @abstractmethod
    async def get_endpoint_health(self, endpoint_name: str) -> Dict[str, Any]:
        """
        Check health status of a registered endpoint.
        
        Args:
            endpoint_name: Name of endpoint to check
            
        Returns:
            Health status including connectivity and latency metrics
        """
        pass
    
    @abstractmethod
    async def enable_compression(self, algorithm: str = "gzip") -> None:
        """
        Enable message compression for bandwidth optimization.
        
        Args:
            algorithm: Compression algorithm to use (gzip, lz4, etc.)
        """
        pass
    
    @abstractmethod
    async def get_transport_statistics(self) -> Dict[str, Any]:
        """
        Get transport statistics and performance metrics.
        
        Returns:
            Dictionary containing:
            - messages_sent: Total messages sent
            - messages_failed: Total failed deliveries
            - bytes_transferred: Total bytes transferred
            - average_latency_ms: Average delivery latency
            - retry_rate: Percentage of messages requiring retries
            - compression_ratio: Data compression ratio if enabled
        """
        pass
    
    @abstractmethod
    async def subscribe_to_receipts(self) -> AsyncIterator[DeliveryReceipt]:
        """
        Subscribe to delivery receipt notifications.
        
        Yields:
            DeliveryReceipt: Delivery confirmations as they arrive
        """
        pass
    
    async def health_check(self) -> Dict[str, Any]:
        """
        Perform health check of secure forwarder component.
        
        Returns:
            Health status including transport statistics and endpoint status
        """
        try:
            stats = await self.get_transport_statistics()
            buffer_status = await self.get_buffer_status()
            
            return {
                "status": "healthy" if self.is_running() else "stopped",
                "initialized": self.is_initialized(),
                "running": self.is_running(),
                "statistics": stats,
                "buffer_status": buffer_status,
                "timestamp": datetime.utcnow().isoformat()
            }
        except Exception as e:
            return {
                "status": "unhealthy",
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }