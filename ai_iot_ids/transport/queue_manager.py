"""
Queue management and backpressure handling for the AI-driven IoT IDS system.

This module provides bounded queues, local buffering with disk persistence,
and data compression for reliable message handling under various load conditions.
"""

import asyncio
import gzip
import json
import lz4.frame
import sqlite3
import threading
import time
import uuid
from collections import deque
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, List, Optional, Generic, TypeVar, Callable, Union
from dataclasses import dataclass, asdict
from enum import Enum
from queue import Queue, Full, Empty

from ..interfaces.secure_forwarder import SecureMessage, MessagePriority
from ..utils.logging_config import get_logger
from ..utils.error_handling import IDSError

T = TypeVar('T')


class CompressionAlgorithm(str, Enum):
    """Supported compression algorithms."""
    NONE = "none"
    GZIP = "gzip"
    LZ4 = "lz4"


class QueueState(str, Enum):
    """Queue operational states."""
    RUNNING = "running"
    PAUSED = "paused"
    DRAINING = "draining"
    STOPPED = "stopped"


@dataclass
class QueueMetrics:
    """Queue performance and utilization metrics."""
    queue_name: str
    current_size: int
    max_size: int
    utilization_percent: float
    messages_enqueued: int
    messages_dequeued: int
    messages_dropped: int
    average_processing_time_ms: float
    oldest_message_age_seconds: float
    compression_ratio: float
    disk_usage_mb: float
    state: QueueState
    last_updated: datetime


@dataclass
class BackpressureConfig:
    """Configuration for backpressure handling."""
    high_watermark_percent: float = 80.0  # Start applying backpressure
    low_watermark_percent: float = 60.0   # Stop applying backpressure
    drop_threshold_percent: float = 95.0  # Start dropping messages
    priority_drop_order: List[MessagePriority] = None  # Order to drop by priority
    enable_sampling: bool = True           # Enable message sampling under pressure
    sampling_rate: float = 0.5            # Sample rate when under pressure
    
    def __post_init__(self):
        if self.priority_drop_order is None:
            self.priority_drop_order = [
                MessagePriority.LOW,
                MessagePriority.NORMAL,
                MessagePriority.HIGH,
                MessagePriority.CRITICAL
            ]


class BoundedQueue(Generic[T]):
    """
    Thread-safe bounded queue with backpressure handling.
    
    Provides configurable size limits, priority-based dropping,
    and comprehensive metrics for monitoring queue health.
    """
    
    def __init__(self, 
                 name: str,
                 max_size: int,
                 backpressure_config: Optional[BackpressureConfig] = None,
                 compression: CompressionAlgorithm = CompressionAlgorithm.NONE):
        self.name = name
        self.max_size = max_size
        self.compression = compression
        self.backpressure_config = backpressure_config or BackpressureConfig()
        
        self.logger = get_logger(__name__)
        
        # Internal queue storage
        self._queue: deque = deque()
        self._lock = threading.RLock()
        self._not_empty = threading.Condition(self._lock)
        self._not_full = threading.Condition(self._lock)
        
        # State management
        self._state = QueueState.RUNNING
        self._shutdown = False
        
        # Metrics
        self._metrics = QueueMetrics(
            queue_name=name,
            current_size=0,
            max_size=max_size,
            utilization_percent=0.0,
            messages_enqueued=0,
            messages_dequeued=0,
            messages_dropped=0,
            average_processing_time_ms=0.0,
            oldest_message_age_seconds=0.0,
            compression_ratio=1.0,
            disk_usage_mb=0.0,
            state=self._state,
            last_updated=datetime.utcnow()
        )
        
        # Processing time tracking
        self._processing_times: deque = deque(maxlen=1000)
        
        # Backpressure state
        self._backpressure_active = False
        self._sampling_active = False
        self._sample_counter = 0
    
    def put(self, item: T, timeout: Optional[float] = None, 
            priority: MessagePriority = MessagePriority.NORMAL) -> bool:
        """
        Put an item into the queue with optional timeout and priority.
        
        Returns:
            True if item was added, False if dropped due to backpressure
        """
        if self._shutdown:
            raise IDSError("Queue is shutdown")
        
        with self._lock:
            # Check if we should drop this message due to backpressure
            if self._should_drop_message(priority):
                self._metrics.messages_dropped += 1
                self.logger.debug(f"Dropped message in queue '{self.name}' due to backpressure")
                return False
            
            # Check if we should sample this message
            if self._sampling_active and not self._should_sample_message():
                self._metrics.messages_dropped += 1
                return False
            
            # Wait for space if queue is full
            end_time = time.time() + timeout if timeout else None
            
            while len(self._queue) >= self.max_size and not self._shutdown:
                if self._state == QueueState.STOPPED:
                    return False
                
                if end_time and time.time() >= end_time:
                    return False
                
                wait_time = min(1.0, end_time - time.time()) if end_time else 1.0
                self._not_full.wait(wait_time)
            
            if self._shutdown:
                return False
            
            # Compress item if compression is enabled
            compressed_item = self._compress_item(item)
            
            # Add item with timestamp for age tracking
            queue_item = {
                'data': compressed_item,
                'priority': priority,
                'timestamp': datetime.utcnow(),
                'original_size': len(str(item)) if hasattr(item, '__len__') else 0,
                'compressed_size': len(str(compressed_item)) if hasattr(compressed_item, '__len__') else 0
            }
            
            self._queue.append(queue_item)
            self._metrics.messages_enqueued += 1
            self._update_metrics()
            
            self._not_empty.notify()
            
            return True
    
    def get(self, timeout: Optional[float] = None) -> Optional[T]:
        """Get an item from the queue with optional timeout."""
        if self._shutdown and len(self._queue) == 0:
            return None
        
        with self._lock:
            end_time = time.time() + timeout if timeout else None
            
            while len(self._queue) == 0 and not self._shutdown:
                if self._state == QueueState.STOPPED:
                    return None
                
                if end_time and time.time() >= end_time:
                    return None
                
                wait_time = min(1.0, end_time - time.time()) if end_time else 1.0
                self._not_empty.wait(wait_time)
            
            if len(self._queue) == 0:
                return None
            
            # Get highest priority item
            queue_item = self._get_highest_priority_item()
            
            if queue_item is None:
                return None
            
            # Decompress item
            item = self._decompress_item(queue_item['data'])
            
            self._metrics.messages_dequeued += 1
            self._update_metrics()
            
            self._not_full.notify()
            
            return item
    
    def put_nowait(self, item: T, priority: MessagePriority = MessagePriority.NORMAL) -> bool:
        """Put an item without waiting."""
        return self.put(item, timeout=0, priority=priority)
    
    def get_nowait(self) -> Optional[T]:
        """Get an item without waiting."""
        return self.get(timeout=0)
    
    def size(self) -> int:
        """Get current queue size."""
        with self._lock:
            return len(self._queue)
    
    def empty(self) -> bool:
        """Check if queue is empty."""
        with self._lock:
            return len(self._queue) == 0
    
    def full(self) -> bool:
        """Check if queue is full."""
        with self._lock:
            return len(self._queue) >= self.max_size
    
    def clear(self) -> int:
        """Clear all items from queue and return count of cleared items."""
        with self._lock:
            cleared_count = len(self._queue)
            self._queue.clear()
            self._update_metrics()
            self._not_full.notify_all()
            return cleared_count
    
    def pause(self) -> None:
        """Pause queue operations."""
        with self._lock:
            self._state = QueueState.PAUSED
            self.logger.info(f"Queue '{self.name}' paused")
    
    def resume(self) -> None:
        """Resume queue operations."""
        with self._lock:
            self._state = QueueState.RUNNING
            self._not_empty.notify_all()
            self._not_full.notify_all()
            self.logger.info(f"Queue '{self.name}' resumed")
    
    def drain(self, timeout: Optional[float] = None) -> List[T]:
        """Drain all items from queue."""
        items = []
        start_time = time.time()
        
        with self._lock:
            self._state = QueueState.DRAINING
        
        while not self.empty():
            if timeout and (time.time() - start_time) > timeout:
                break
            
            item = self.get_nowait()
            if item is not None:
                items.append(item)
        
        with self._lock:
            self._state = QueueState.RUNNING
        
        self.logger.info(f"Drained {len(items)} items from queue '{self.name}'")
        return items
    
    def shutdown(self) -> None:
        """Shutdown the queue."""
        with self._lock:
            self._shutdown = True
            self._state = QueueState.STOPPED
            self._not_empty.notify_all()
            self._not_full.notify_all()
        
        self.logger.info(f"Queue '{self.name}' shutdown")
    
    def get_metrics(self) -> QueueMetrics:
        """Get current queue metrics."""
        with self._lock:
            self._update_metrics()
            return self._metrics
    
    def _should_drop_message(self, priority: MessagePriority) -> bool:
        """Determine if a message should be dropped due to backpressure."""
        utilization = (len(self._queue) / self.max_size) * 100
        
        # Update backpressure state
        if utilization >= self.backpressure_config.high_watermark_percent:
            self._backpressure_active = True
        elif utilization <= self.backpressure_config.low_watermark_percent:
            self._backpressure_active = False
        
        # Update sampling state
        if utilization >= self.backpressure_config.high_watermark_percent:
            self._sampling_active = self.backpressure_config.enable_sampling
        else:
            self._sampling_active = False
        
        # Drop if above drop threshold
        if utilization >= self.backpressure_config.drop_threshold_percent:
            # Drop based on priority order
            priority_index = self.backpressure_config.priority_drop_order.index(priority)
            drop_priorities = len(self.backpressure_config.priority_drop_order) - 1
            
            # Higher utilization = drop more priority levels
            drop_level = int((utilization - self.backpressure_config.drop_threshold_percent) / 
                           (100 - self.backpressure_config.drop_threshold_percent) * drop_priorities)
            
            return priority_index <= drop_level
        
        return False
    
    def _should_sample_message(self) -> bool:
        """Determine if a message should be sampled."""
        if not self._sampling_active:
            return True
        
        self._sample_counter += 1
        return (self._sample_counter % int(1 / self.backpressure_config.sampling_rate)) == 0
    
    def _get_highest_priority_item(self) -> Optional[Dict[str, Any]]:
        """Get the highest priority item from the queue."""
        if not self._queue:
            return None
        
        # Find highest priority item
        highest_priority_idx = 0
        highest_priority = MessagePriority.LOW
        
        for i, item in enumerate(self._queue):
            item_priority = item['priority']
            if self._priority_value(item_priority) > self._priority_value(highest_priority):
                highest_priority = item_priority
                highest_priority_idx = i
        
        # Remove and return the highest priority item
        if highest_priority_idx == 0:
            return self._queue.popleft()
        elif highest_priority_idx == len(self._queue) - 1:
            return self._queue.pop()
        else:
            # Remove from middle (less efficient but maintains priority)
            item = self._queue[highest_priority_idx]
            del self._queue[highest_priority_idx]
            return item
    
    def _priority_value(self, priority: MessagePriority) -> int:
        """Convert priority to numeric value for comparison."""
        priority_values = {
            MessagePriority.LOW: 1,
            MessagePriority.NORMAL: 2,
            MessagePriority.HIGH: 3,
            MessagePriority.CRITICAL: 4
        }
        return priority_values.get(priority, 1)
    
    def _compress_item(self, item: T) -> Union[T, bytes]:
        """Compress item if compression is enabled."""
        if self.compression == CompressionAlgorithm.NONE:
            return item
        
        try:
            # Convert item to JSON string
            if isinstance(item, (dict, list)):
                item_str = json.dumps(item)
            else:
                item_str = str(item)
            
            item_bytes = item_str.encode('utf-8')
            
            if self.compression == CompressionAlgorithm.GZIP:
                return gzip.compress(item_bytes)
            elif self.compression == CompressionAlgorithm.LZ4:
                return lz4.frame.compress(item_bytes)
            
        except Exception as e:
            self.logger.warning(f"Failed to compress item: {e}")
        
        return item
    
    def _decompress_item(self, item: Union[T, bytes]) -> T:
        """Decompress item if it was compressed."""
        if self.compression == CompressionAlgorithm.NONE or not isinstance(item, bytes):
            return item
        
        try:
            if self.compression == CompressionAlgorithm.GZIP:
                decompressed_bytes = gzip.decompress(item)
            elif self.compression == CompressionAlgorithm.LZ4:
                decompressed_bytes = lz4.frame.decompress(item)
            else:
                return item
            
            decompressed_str = decompressed_bytes.decode('utf-8')
            
            # Try to parse as JSON, fallback to string
            try:
                return json.loads(decompressed_str)
            except json.JSONDecodeError:
                return decompressed_str
                
        except Exception as e:
            self.logger.warning(f"Failed to decompress item: {e}")
        
        return item
    
    def _update_metrics(self) -> None:
        """Update queue metrics."""
        current_size = len(self._queue)
        self._metrics.current_size = current_size
        self._metrics.utilization_percent = (current_size / self.max_size) * 100
        self._metrics.state = self._state
        self._metrics.last_updated = datetime.utcnow()
        
        # Calculate oldest message age
        if self._queue:
            oldest_timestamp = min(item['timestamp'] for item in self._queue)
            self._metrics.oldest_message_age_seconds = (
                datetime.utcnow() - oldest_timestamp
            ).total_seconds()
        else:
            self._metrics.oldest_message_age_seconds = 0.0
        
        # Calculate average processing time
        if self._processing_times:
            self._metrics.average_processing_time_ms = sum(self._processing_times) / len(self._processing_times)
        
        # Calculate compression ratio
        if self._queue and self.compression != CompressionAlgorithm.NONE:
            total_original = sum(item.get('original_size', 0) for item in self._queue)
            total_compressed = sum(item.get('compressed_size', 0) for item in self._queue)
            
            if total_original > 0:
                self._metrics.compression_ratio = total_compressed / total_original


class PersistentQueue:
    """
    Persistent queue with SQLite backend for reliable message storage.
    
    Provides disk-based persistence for messages that survive process
    restarts and system failures.
    """
    
    def __init__(self, 
                 name: str,
                 db_path: str,
                 max_size_mb: int = 100,
                 compression: CompressionAlgorithm = CompressionAlgorithm.GZIP):
        self.name = name
        self.db_path = Path(db_path)
        self.max_size_mb = max_size_mb
        self.compression = compression
        
        self.logger = get_logger(__name__)
        
        # Create database directory
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Initialize database
        self._init_database()
        
        # Metrics
        self._messages_stored = 0
        self._messages_retrieved = 0
        self._total_size_bytes = 0
    
    def _init_database(self) -> None:
        """Initialize SQLite database."""
        try:
            conn = sqlite3.connect(str(self.db_path))
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS queue_messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    message_id TEXT UNIQUE,
                    priority INTEGER,
                    timestamp TEXT,
                    data BLOB,
                    original_size INTEGER,
                    compressed_size INTEGER,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_priority_timestamp 
                ON queue_messages(priority DESC, timestamp ASC)
            """)
            
            conn.commit()
            conn.close()
            
            self.logger.info(f"Persistent queue '{self.name}' initialized: {self.db_path}")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize persistent queue database: {e}")
            raise IDSError(f"Database initialization failed: {e}")
    
    def put(self, message_id: str, data: Any, 
            priority: MessagePriority = MessagePriority.NORMAL) -> bool:
        """Store a message in the persistent queue."""
        try:
            # Serialize and compress data
            if isinstance(data, (dict, list)):
                data_str = json.dumps(data)
            else:
                data_str = str(data)
            
            original_size = len(data_str.encode('utf-8'))
            
            if self.compression == CompressionAlgorithm.GZIP:
                compressed_data = gzip.compress(data_str.encode('utf-8'))
            elif self.compression == CompressionAlgorithm.LZ4:
                compressed_data = lz4.frame.compress(data_str.encode('utf-8'))
            else:
                compressed_data = data_str.encode('utf-8')
            
            compressed_size = len(compressed_data)
            
            # Check size limits
            if self._total_size_bytes + compressed_size > self.max_size_mb * 1024 * 1024:
                self.logger.warning(f"Persistent queue '{self.name}' size limit exceeded")
                return False
            
            # Store in database
            conn = sqlite3.connect(str(self.db_path))
            
            conn.execute("""
                INSERT OR REPLACE INTO queue_messages 
                (message_id, priority, timestamp, data, original_size, compressed_size)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                message_id,
                self._priority_value(priority),
                datetime.utcnow().isoformat(),
                compressed_data,
                original_size,
                compressed_size
            ))
            
            conn.commit()
            conn.close()
            
            self._messages_stored += 1
            self._total_size_bytes += compressed_size
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to store message in persistent queue: {e}")
            return False
    
    def get(self) -> Optional[Dict[str, Any]]:
        """Retrieve the highest priority message from the queue."""
        try:
            conn = sqlite3.connect(str(self.db_path))
            
            # Get highest priority, oldest message
            cursor = conn.execute("""
                SELECT id, message_id, priority, timestamp, data, original_size, compressed_size
                FROM queue_messages
                ORDER BY priority DESC, timestamp ASC
                LIMIT 1
            """)
            
            row = cursor.fetchone()
            
            if row is None:
                conn.close()
                return None
            
            msg_id, message_id, priority, timestamp, data, original_size, compressed_size = row
            
            # Delete the message
            conn.execute("DELETE FROM queue_messages WHERE id = ?", (msg_id,))
            conn.commit()
            conn.close()
            
            # Decompress data
            if self.compression == CompressionAlgorithm.GZIP:
                decompressed_data = gzip.decompress(data).decode('utf-8')
            elif self.compression == CompressionAlgorithm.LZ4:
                decompressed_data = lz4.frame.decompress(data).decode('utf-8')
            else:
                decompressed_data = data.decode('utf-8')
            
            # Try to parse as JSON
            try:
                parsed_data = json.loads(decompressed_data)
            except json.JSONDecodeError:
                parsed_data = decompressed_data
            
            self._messages_retrieved += 1
            self._total_size_bytes -= compressed_size
            
            return {
                'message_id': message_id,
                'priority': self._value_to_priority(priority),
                'timestamp': datetime.fromisoformat(timestamp),
                'data': parsed_data,
                'original_size': original_size,
                'compressed_size': compressed_size
            }
            
        except Exception as e:
            self.logger.error(f"Failed to retrieve message from persistent queue: {e}")
            return None
    
    def size(self) -> int:
        """Get number of messages in the queue."""
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.execute("SELECT COUNT(*) FROM queue_messages")
            count = cursor.fetchone()[0]
            conn.close()
            return count
        except Exception as e:
            self.logger.error(f"Failed to get queue size: {e}")
            return 0
    
    def clear(self) -> int:
        """Clear all messages from the queue."""
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.execute("SELECT COUNT(*) FROM queue_messages")
            count = cursor.fetchone()[0]
            
            conn.execute("DELETE FROM queue_messages")
            conn.commit()
            conn.close()
            
            self._total_size_bytes = 0
            self.logger.info(f"Cleared {count} messages from persistent queue '{self.name}'")
            return count
            
        except Exception as e:
            self.logger.error(f"Failed to clear persistent queue: {e}")
            return 0
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get persistent queue metrics."""
        return {
            "name": self.name,
            "messages_stored": self._messages_stored,
            "messages_retrieved": self._messages_retrieved,
            "current_size": self.size(),
            "total_size_bytes": self._total_size_bytes,
            "max_size_mb": self.max_size_mb,
            "utilization_percent": (self._total_size_bytes / (self.max_size_mb * 1024 * 1024)) * 100,
            "compression": self.compression.value,
            "db_path": str(self.db_path)
        }
    
    def _priority_value(self, priority: MessagePriority) -> int:
        """Convert priority to numeric value."""
        priority_values = {
            MessagePriority.LOW: 1,
            MessagePriority.NORMAL: 2,
            MessagePriority.HIGH: 3,
            MessagePriority.CRITICAL: 4
        }
        return priority_values.get(priority, 2)
    
    def _value_to_priority(self, value: int) -> MessagePriority:
        """Convert numeric value to priority."""
        value_to_priority = {
            1: MessagePriority.LOW,
            2: MessagePriority.NORMAL,
            3: MessagePriority.HIGH,
            4: MessagePriority.CRITICAL
        }
        return value_to_priority.get(value, MessagePriority.NORMAL)


class QueueManager:
    """
    Manager for multiple queues with backpressure handling.
    
    Provides centralized management of bounded queues and persistent
    queues with comprehensive monitoring and control capabilities.
    """
    
    def __init__(self):
        self.logger = get_logger(__name__)
        self._bounded_queues: Dict[str, BoundedQueue] = {}
        self._persistent_queues: Dict[str, PersistentQueue] = {}
        self._running = False
        
        # Global metrics
        self._global_metrics = {
            "total_messages_enqueued": 0,
            "total_messages_dequeued": 0,
            "total_messages_dropped": 0,
            "active_queues": 0,
            "total_memory_usage_mb": 0,
            "total_disk_usage_mb": 0
        }
    
    def create_bounded_queue(self, 
                           name: str,
                           max_size: int,
                           backpressure_config: Optional[BackpressureConfig] = None,
                           compression: CompressionAlgorithm = CompressionAlgorithm.NONE) -> BoundedQueue:
        """Create a new bounded queue."""
        if name in self._bounded_queues:
            raise IDSError(f"Bounded queue '{name}' already exists")
        
        queue = BoundedQueue(name, max_size, backpressure_config, compression)
        self._bounded_queues[name] = queue
        
        self.logger.info(f"Created bounded queue '{name}' with max_size={max_size}")
        return queue
    
    def create_persistent_queue(self,
                              name: str,
                              db_path: str,
                              max_size_mb: int = 100,
                              compression: CompressionAlgorithm = CompressionAlgorithm.GZIP) -> PersistentQueue:
        """Create a new persistent queue."""
        if name in self._persistent_queues:
            raise IDSError(f"Persistent queue '{name}' already exists")
        
        queue = PersistentQueue(name, db_path, max_size_mb, compression)
        self._persistent_queues[name] = queue
        
        self.logger.info(f"Created persistent queue '{name}' at {db_path}")
        return queue
    
    def get_bounded_queue(self, name: str) -> Optional[BoundedQueue]:
        """Get a bounded queue by name."""
        return self._bounded_queues.get(name)
    
    def get_persistent_queue(self, name: str) -> Optional[PersistentQueue]:
        """Get a persistent queue by name."""
        return self._persistent_queues.get(name)
    
    def remove_queue(self, name: str) -> bool:
        """Remove a queue by name."""
        removed = False
        
        if name in self._bounded_queues:
            self._bounded_queues[name].shutdown()
            del self._bounded_queues[name]
            removed = True
        
        if name in self._persistent_queues:
            del self._persistent_queues[name]
            removed = True
        
        if removed:
            self.logger.info(f"Removed queue '{name}'")
        
        return removed
    
    def get_all_metrics(self) -> Dict[str, Any]:
        """Get metrics for all queues."""
        metrics = {
            "bounded_queues": {},
            "persistent_queues": {},
            "global_metrics": self._global_metrics.copy()
        }
        
        # Collect bounded queue metrics
        for name, queue in self._bounded_queues.items():
            metrics["bounded_queues"][name] = asdict(queue.get_metrics())
        
        # Collect persistent queue metrics
        for name, queue in self._persistent_queues.items():
            metrics["persistent_queues"][name] = queue.get_metrics()
        
        # Update global metrics
        total_enqueued = sum(q.get_metrics().messages_enqueued for q in self._bounded_queues.values())
        total_dequeued = sum(q.get_metrics().messages_dequeued for q in self._bounded_queues.values())
        total_dropped = sum(q.get_metrics().messages_dropped for q in self._bounded_queues.values())
        
        metrics["global_metrics"].update({
            "total_messages_enqueued": total_enqueued,
            "total_messages_dequeued": total_dequeued,
            "total_messages_dropped": total_dropped,
            "active_queues": len(self._bounded_queues) + len(self._persistent_queues)
        })
        
        return metrics
    
    def pause_all_queues(self) -> None:
        """Pause all bounded queues."""
        for queue in self._bounded_queues.values():
            queue.pause()
        
        self.logger.info("Paused all bounded queues")
    
    def resume_all_queues(self) -> None:
        """Resume all bounded queues."""
        for queue in self._bounded_queues.values():
            queue.resume()
        
        self.logger.info("Resumed all bounded queues")
    
    def shutdown_all_queues(self) -> None:
        """Shutdown all queues."""
        for queue in self._bounded_queues.values():
            queue.shutdown()
        
        self._bounded_queues.clear()
        self._persistent_queues.clear()
        
        self.logger.info("Shutdown all queues")
    
    def get_health_status(self) -> Dict[str, Any]:
        """Get overall health status of queue manager."""
        total_queues = len(self._bounded_queues) + len(self._persistent_queues)
        healthy_queues = 0
        
        # Check bounded queues
        for queue in self._bounded_queues.values():
            metrics = queue.get_metrics()
            if metrics.state in [QueueState.RUNNING, QueueState.PAUSED]:
                healthy_queues += 1
        
        # Persistent queues are considered healthy if they exist
        healthy_queues += len(self._persistent_queues)
        
        health_percentage = (healthy_queues / total_queues * 100) if total_queues > 0 else 100
        
        return {
            "status": "healthy" if health_percentage >= 80 else "degraded" if health_percentage >= 50 else "unhealthy",
            "total_queues": total_queues,
            "healthy_queues": healthy_queues,
            "health_percentage": health_percentage,
            "bounded_queues": len(self._bounded_queues),
            "persistent_queues": len(self._persistent_queues),
            "timestamp": datetime.utcnow().isoformat()
        }