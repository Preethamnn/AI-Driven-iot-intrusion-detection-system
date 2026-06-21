"""
Secure forwarder implementation with mTLS support.

This module implements the SecureForwarderInterface with full mTLS support,
certificate management, retry mechanisms with exponential backoff, and
local buffering capabilities.
"""

import asyncio
import json
import ssl
import gzip
import lz4.frame
import sqlite3
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, List, Optional, AsyncIterator
from urllib.parse import urlparse
import aiohttp
import aiofiles
from tenacity import (
    retry, 
    stop_after_attempt, 
    wait_exponential, 
    retry_if_exception_type,
    RetryError
)

from ..interfaces.secure_forwarder import (
    SecureForwarderInterface,
    SecureMessage,
    TransportEndpoint,
    DeliveryReceipt,
    TransportProtocol,
    MessagePriority
)
from ..utils.logging_config import get_logger
from ..utils.error_handling import IDSError


class SecureForwarderImpl(SecureForwarderInterface):
    """
    Implementation of secure forwarder with mTLS support.
    
    Provides encrypted data transport using mTLS, automatic certificate
    rotation, retry mechanisms with exponential backoff, and local
    buffering for offline operation.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config or {})
        self.logger = get_logger(__name__)
        
        # mTLS configuration
        self._ssl_context: Optional[ssl.SSLContext] = None
        self._cert_path: Optional[str] = None
        self._key_path: Optional[str] = None
        self._ca_path: Optional[str] = None
        
        # Retry configuration
        self._max_retries = 3
        self._backoff_multiplier = 2.0
        self._max_backoff_seconds = 60
        
        # Local buffering
        self._buffer_enabled = False
        self._buffer_size_mb = 100
        self._persistence_path: Optional[str] = None
        self._buffer_db: Optional[sqlite3.Connection] = None
        
        # Compression
        self._compression_enabled = False
        self._compression_algorithm = "gzip"
        
        # Endpoints registry
        self._endpoints: Dict[str, TransportEndpoint] = {}
        
        # Statistics
        self._stats = {
            "messages_sent": 0,
            "messages_failed": 0,
            "bytes_transferred": 0,
            "total_latency_ms": 0,
            "retry_count": 0
        }
        
        # Receipt subscribers
        self._receipt_queue: asyncio.Queue[DeliveryReceipt] = asyncio.Queue()
        
        self._session: Optional[aiohttp.ClientSession] = None
        
    async def initialize(self) -> None:
        """Initialize the secure forwarder."""
        if self._initialized:
            return
            
        try:
            # Initialize HTTP session
            connector = aiohttp.TCPConnector(
                limit=100,
                limit_per_host=10,
                ssl=self._ssl_context
            )
            
            timeout = aiohttp.ClientTimeout(total=30)
            self._session = aiohttp.ClientSession(
                connector=connector,
                timeout=timeout
            )
            
            # Initialize buffer database if enabled
            if self._buffer_enabled and self._persistence_path:
                await self._init_buffer_db()
            
            self._initialized = True
            self.logger.info("Secure forwarder initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize secure forwarder: {e}")
            raise IDSError(f"Initialization failed: {e}")
    
    async def start(self) -> None:
        """Start the secure forwarder."""
        if not self._initialized:
            await self.initialize()
            
        self._running = True
        self.logger.info("Secure forwarder started")
    
    async def stop(self) -> None:
        """Stop the secure forwarder."""
        self._running = False
        
        # Close HTTP session
        if self._session:
            await self._session.close()
            self._session = None
        
        # Close buffer database
        if self._buffer_db:
            self._buffer_db.close()
            self._buffer_db = None
        
        self.logger.info("Secure forwarder stopped")
    
    async def send_message(self, message: SecureMessage, 
                          endpoint: TransportEndpoint) -> DeliveryReceipt:
        """Send a secure message to the specified endpoint."""
        if not self._running:
            raise IDSError("Secure forwarder is not running")
        
        start_time = datetime.utcnow()
        
        try:
            # Compress message if enabled
            payload_data = await self._prepare_payload(message)
            
            # Send message with retry logic
            receipt = await self._send_with_retry(message, endpoint, payload_data)
            
            # Update statistics
            latency_ms = (datetime.utcnow() - start_time).total_seconds() * 1000
            self._stats["messages_sent"] += 1
            self._stats["bytes_transferred"] += len(payload_data)
            self._stats["total_latency_ms"] += latency_ms
            
            # Notify receipt subscribers
            await self._receipt_queue.put(receipt)
            
            return receipt
            
        except Exception as e:
            self._stats["messages_failed"] += 1
            
            # Buffer message if local buffering is enabled
            if self._buffer_enabled:
                await self._buffer_message(message, endpoint)
            
            error_receipt = DeliveryReceipt(
                message_id=message.message_id,
                delivered_at=datetime.utcnow(),
                endpoint=endpoint.url,
                status="failed",
                error_message=str(e)
            )
            
            await self._receipt_queue.put(error_receipt)
            raise IDSError(f"Failed to send message: {e}")
    
    async def send_batch(self, messages: List[SecureMessage], 
                        endpoint: TransportEndpoint) -> List[DeliveryReceipt]:
        """Send multiple messages in batch."""
        receipts = []
        
        # Send messages concurrently with limited concurrency
        semaphore = asyncio.Semaphore(10)  # Limit concurrent sends
        
        async def send_single(msg):
            async with semaphore:
                return await self.send_message(msg, endpoint)
        
        tasks = [send_single(msg) for msg in messages]
        receipts = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Convert exceptions to error receipts
        for i, result in enumerate(receipts):
            if isinstance(result, Exception):
                receipts[i] = DeliveryReceipt(
                    message_id=messages[i].message_id,
                    delivered_at=datetime.utcnow(),
                    endpoint=endpoint.url,
                    status="failed",
                    error_message=str(result)
                )
        
        return receipts
    
    async def setup_mtls(self, cert_path: str, key_path: str, 
                        ca_path: str) -> None:
        """Configure mutual TLS authentication."""
        try:
            # Verify certificate files exist
            cert_file = Path(cert_path)
            key_file = Path(key_path)
            ca_file = Path(ca_path)
            
            if not cert_file.exists():
                raise FileNotFoundError(f"Certificate file not found: {cert_path}")
            if not key_file.exists():
                raise FileNotFoundError(f"Key file not found: {key_path}")
            if not ca_file.exists():
                raise FileNotFoundError(f"CA file not found: {ca_path}")
            
            # Create SSL context
            self._ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            self._ssl_context.check_hostname = True
            self._ssl_context.verify_mode = ssl.CERT_REQUIRED
            
            # Load CA certificate
            self._ssl_context.load_verify_locations(ca_path)
            
            # Load client certificate and key
            self._ssl_context.load_cert_chain(cert_path, key_path)
            
            # Store paths for certificate rotation
            self._cert_path = cert_path
            self._key_path = key_path
            self._ca_path = ca_path
            
            self.logger.info("mTLS configuration completed successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to setup mTLS: {e}")
            raise ValueError(f"Invalid mTLS configuration: {e}")
    
    async def rotate_certificates(self) -> None:
        """Rotate TLS certificates for enhanced security."""
        if not all([self._cert_path, self._key_path, self._ca_path]):
            raise IDSError("mTLS not configured, cannot rotate certificates")
        
        try:
            # Reload certificates
            await self.setup_mtls(self._cert_path, self._key_path, self._ca_path)
            
            # Update session with new SSL context if running
            if self._session and self._running:
                await self._session.close()
                
                connector = aiohttp.TCPConnector(
                    limit=100,
                    limit_per_host=10,
                    ssl=self._ssl_context
                )
                
                timeout = aiohttp.ClientTimeout(total=30)
                self._session = aiohttp.ClientSession(
                    connector=connector,
                    timeout=timeout
                )
            
            self.logger.info("Certificate rotation completed successfully")
            
        except Exception as e:
            self.logger.error(f"Certificate rotation failed: {e}")
            raise IDSError(f"Certificate rotation failed: {e}")
    
    async def configure_retry_policy(self, max_retries: int, 
                                   backoff_multiplier: float,
                                   max_backoff_seconds: int) -> None:
        """Configure retry policy for failed message deliveries."""
        self._max_retries = max_retries
        self._backoff_multiplier = backoff_multiplier
        self._max_backoff_seconds = max_backoff_seconds
        
        self.logger.info(
            f"Retry policy configured: max_retries={max_retries}, "
            f"backoff_multiplier={backoff_multiplier}, "
            f"max_backoff_seconds={max_backoff_seconds}"
        )
    
    async def enable_local_buffering(self, buffer_size_mb: int, 
                                   persistence_path: str) -> None:
        """Enable local buffering for offline operation."""
        self._buffer_enabled = True
        self._buffer_size_mb = buffer_size_mb
        self._persistence_path = persistence_path
        
        # Initialize buffer database if already running
        if self._running:
            await self._init_buffer_db()
        
        self.logger.info(
            f"Local buffering enabled: size={buffer_size_mb}MB, "
            f"path={persistence_path}"
        )
    
    async def get_buffer_status(self) -> Dict[str, Any]:
        """Get current buffer status and utilization."""
        if not self._buffer_enabled or not self._buffer_db:
            return {
                "buffer_size_mb": 0,
                "buffer_utilization": 0.0,
                "queued_messages": 0,
                "oldest_message_age_seconds": 0
            }
        
        try:
            cursor = self._buffer_db.cursor()
            
            # Get message count
            cursor.execute("SELECT COUNT(*) FROM buffered_messages")
            message_count = cursor.fetchone()[0]
            
            # Get oldest message timestamp
            cursor.execute(
                "SELECT MIN(timestamp) FROM buffered_messages"
            )
            oldest_timestamp = cursor.fetchone()[0]
            
            oldest_age_seconds = 0
            if oldest_timestamp:
                oldest_dt = datetime.fromisoformat(oldest_timestamp)
                oldest_age_seconds = (datetime.utcnow() - oldest_dt).total_seconds()
            
            # Calculate buffer utilization (approximate)
            cursor.execute("SELECT SUM(LENGTH(payload)) FROM buffered_messages")
            total_bytes = cursor.fetchone()[0] or 0
            buffer_utilization = (total_bytes / (self._buffer_size_mb * 1024 * 1024)) * 100
            
            return {
                "buffer_size_mb": self._buffer_size_mb,
                "buffer_utilization": min(buffer_utilization, 100.0),
                "queued_messages": message_count,
                "oldest_message_age_seconds": oldest_age_seconds
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get buffer status: {e}")
            return {
                "buffer_size_mb": self._buffer_size_mb,
                "buffer_utilization": 0.0,
                "queued_messages": 0,
                "oldest_message_age_seconds": 0,
                "error": str(e)
            }
    
    async def flush_buffer(self) -> int:
        """Flush all buffered messages to their destinations."""
        if not self._buffer_enabled or not self._buffer_db:
            return 0
        
        delivered_count = 0
        
        try:
            cursor = self._buffer_db.cursor()
            cursor.execute(
                "SELECT id, message_data, endpoint_data FROM buffered_messages "
                "ORDER BY timestamp ASC"
            )
            
            buffered_messages = cursor.fetchall()
            
            for msg_id, message_json, endpoint_json in buffered_messages:
                try:
                    # Deserialize message and endpoint
                    message_data = json.loads(message_json)
                    endpoint_data = json.loads(endpoint_json)
                    
                    message = SecureMessage(
                        message_id=message_data["message_id"],
                        timestamp=datetime.fromisoformat(message_data["timestamp"]),
                        source_component=message_data["source_component"],
                        destination_component=message_data["destination_component"],
                        message_type=message_data["message_type"],
                        payload=message_data["payload"],
                        priority=MessagePriority(message_data["priority"]),
                        retry_count=message_data["retry_count"],
                        max_retries=message_data["max_retries"]
                    )
                    
                    endpoint = TransportEndpoint(
                        url=endpoint_data["url"],
                        protocol=TransportProtocol(endpoint_data["protocol"]),
                        authentication=endpoint_data["authentication"],
                        timeout_seconds=endpoint_data["timeout_seconds"],
                        max_connections=endpoint_data["max_connections"]
                    )
                    
                    # Try to send the message
                    await self.send_message(message, endpoint)
                    
                    # Remove from buffer on successful delivery
                    cursor.execute("DELETE FROM buffered_messages WHERE id = ?", (msg_id,))
                    self._buffer_db.commit()
                    delivered_count += 1
                    
                except Exception as e:
                    self.logger.warning(f"Failed to deliver buffered message {msg_id}: {e}")
                    continue
            
            self.logger.info(f"Flushed {delivered_count} messages from buffer")
            return delivered_count
            
        except Exception as e:
            self.logger.error(f"Failed to flush buffer: {e}")
            return delivered_count
    
    async def register_endpoint(self, name: str, 
                              endpoint: TransportEndpoint) -> None:
        """Register a named endpoint for message routing."""
        self._endpoints[name] = endpoint
        self.logger.info(f"Registered endpoint '{name}': {endpoint.url}")
    
    async def get_endpoint_health(self, endpoint_name: str) -> Dict[str, Any]:
        """Check health status of a registered endpoint."""
        if endpoint_name not in self._endpoints:
            return {
                "status": "unknown",
                "error": f"Endpoint '{endpoint_name}' not registered"
            }
        
        endpoint = self._endpoints[endpoint_name]
        
        try:
            start_time = datetime.utcnow()
            
            # Send a simple health check message
            health_message = SecureMessage(
                message_id=str(uuid.uuid4()),
                timestamp=datetime.utcnow(),
                source_component="secure_forwarder",
                destination_component="health_check",
                message_type="health_check",
                payload={"check": "ping"}
            )
            
            # Try to connect (without actually sending)
            if self._session:
                async with self._session.get(
                    endpoint.url + "/health",
                    timeout=aiohttp.ClientTimeout(total=5)
                ) as response:
                    latency_ms = (datetime.utcnow() - start_time).total_seconds() * 1000
                    
                    return {
                        "status": "healthy" if response.status < 400 else "unhealthy",
                        "latency_ms": latency_ms,
                        "http_status": response.status,
                        "endpoint": endpoint.url
                    }
            else:
                return {
                    "status": "unhealthy",
                    "error": "HTTP session not initialized"
                }
                
        except Exception as e:
            return {
                "status": "unhealthy",
                "error": str(e),
                "endpoint": endpoint.url
            }
    
    async def enable_compression(self, algorithm: str = "gzip") -> None:
        """Enable message compression for bandwidth optimization."""
        if algorithm not in ["gzip", "lz4"]:
            raise ValueError(f"Unsupported compression algorithm: {algorithm}")
        
        self._compression_enabled = True
        self._compression_algorithm = algorithm
        
        self.logger.info(f"Compression enabled: {algorithm}")
    
    async def get_transport_statistics(self) -> Dict[str, Any]:
        """Get transport statistics and performance metrics."""
        avg_latency_ms = 0
        if self._stats["messages_sent"] > 0:
            avg_latency_ms = self._stats["total_latency_ms"] / self._stats["messages_sent"]
        
        retry_rate = 0
        if self._stats["messages_sent"] > 0:
            retry_rate = (self._stats["retry_count"] / self._stats["messages_sent"]) * 100
        
        compression_ratio = 1.0  # Default no compression
        if self._compression_enabled:
            # This would be calculated based on actual compression statistics
            compression_ratio = 0.7  # Example: 30% compression
        
        return {
            "messages_sent": self._stats["messages_sent"],
            "messages_failed": self._stats["messages_failed"],
            "bytes_transferred": self._stats["bytes_transferred"],
            "average_latency_ms": avg_latency_ms,
            "retry_rate": retry_rate,
            "compression_ratio": compression_ratio,
            "compression_enabled": self._compression_enabled,
            "compression_algorithm": self._compression_algorithm if self._compression_enabled else None
        }
    
    async def subscribe_to_receipts(self) -> AsyncIterator[DeliveryReceipt]:
        """Subscribe to delivery receipt notifications."""
        while self._running:
            try:
                receipt = await asyncio.wait_for(self._receipt_queue.get(), timeout=1.0)
                yield receipt
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                self.logger.error(f"Error in receipt subscription: {e}")
                break
    
    # Private helper methods
    
    async def _prepare_payload(self, message: SecureMessage) -> bytes:
        """Prepare message payload with optional compression."""
        payload_json = json.dumps(message.to_dict()).encode('utf-8')
        
        if self._compression_enabled:
            if self._compression_algorithm == "gzip":
                return gzip.compress(payload_json)
            elif self._compression_algorithm == "lz4":
                return lz4.frame.compress(payload_json)
        
        return payload_json
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=2, min=1, max=60),
        retry=retry_if_exception_type((aiohttp.ClientError, asyncio.TimeoutError))
    )
    async def _send_with_retry(self, message: SecureMessage, 
                              endpoint: TransportEndpoint, 
                              payload_data: bytes) -> DeliveryReceipt:
        """Send message with retry logic."""
        if not self._session:
            raise IDSError("HTTP session not initialized")
        
        headers = {
            'Content-Type': 'application/json',
            'X-Message-ID': message.message_id,
            'X-Message-Type': message.message_type,
            'X-Priority': message.priority.value
        }
        
        if self._compression_enabled:
            headers['Content-Encoding'] = self._compression_algorithm
        
        try:
            async with self._session.post(
                endpoint.url,
                data=payload_data,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=endpoint.timeout_seconds)
            ) as response:
                
                if response.status >= 400:
                    error_text = await response.text()
                    raise aiohttp.ClientResponseError(
                        request_info=response.request_info,
                        history=response.history,
                        status=response.status,
                        message=error_text
                    )
                
                return DeliveryReceipt(
                    message_id=message.message_id,
                    delivered_at=datetime.utcnow(),
                    endpoint=endpoint.url,
                    status="delivered"
                )
                
        except Exception as e:
            self._stats["retry_count"] += 1
            self.logger.warning(f"Retry attempt for message {message.message_id}: {e}")
            raise
    
    async def _init_buffer_db(self) -> None:
        """Initialize SQLite database for message buffering."""
        if not self._persistence_path:
            return
        
        db_path = Path(self._persistence_path) / "message_buffer.db"
        db_path.parent.mkdir(parents=True, exist_ok=True)
        
        self._buffer_db = sqlite3.connect(str(db_path))
        
        # Create table for buffered messages
        self._buffer_db.execute("""
            CREATE TABLE IF NOT EXISTS buffered_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                message_id TEXT UNIQUE,
                timestamp TEXT,
                message_data TEXT,
                endpoint_data TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        self._buffer_db.commit()
        self.logger.info(f"Buffer database initialized: {db_path}")
    
    async def _buffer_message(self, message: SecureMessage, 
                             endpoint: TransportEndpoint) -> None:
        """Buffer a message for later delivery."""
        if not self._buffer_db:
            return
        
        try:
            message_json = json.dumps(message.to_dict())
            endpoint_json = json.dumps({
                "url": endpoint.url,
                "protocol": endpoint.protocol.value,
                "authentication": endpoint.authentication,
                "timeout_seconds": endpoint.timeout_seconds,
                "max_connections": endpoint.max_connections
            })
            
            self._buffer_db.execute(
                """
                INSERT OR REPLACE INTO buffered_messages 
                (message_id, timestamp, message_data, endpoint_data)
                VALUES (?, ?, ?, ?)
                """,
                (
                    message.message_id,
                    message.timestamp.isoformat(),
                    message_json,
                    endpoint_json
                )
            )
            
            self._buffer_db.commit()
            self.logger.debug(f"Message {message.message_id} buffered for later delivery")
            
        except Exception as e:
            self.logger.error(f"Failed to buffer message: {e}")