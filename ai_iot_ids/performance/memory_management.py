"""Memory management and bounded queue implementations."""

import os
import logging
import threading
import time
import gc
import psutil
from typing import Any, Optional, List, Dict, Generic, TypeVar, Callable
from collections import deque
from queue import Queue, Empty, Full
import weakref

logger = logging.getLogger(__name__)

T = TypeVar('T')


class BoundedQueue(Generic[T]):
    """Thread-safe bounded queue with memory management."""
    
    def __init__(self, maxsize: int, drop_policy: str = 'oldest'):
        """Initialize bounded queue.
        
        Args:
            maxsize: Maximum number of items in queue
            drop_policy: Policy for dropping items ('oldest', 'newest', 'random')
        """
        self.maxsize = maxsize
        self.drop_policy = drop_policy
        self._queue = deque(maxlen=maxsize)
        self._lock = threading.RLock()
        self._not_empty = threading.Condition(self._lock)
        self._not_full = threading.Condition(self._lock)
        self._dropped_count = 0
        
    def put(self, item: T, block: bool = True, timeout: Optional[float] = None) -> bool:
        """Put an item into the queue.
        
        Args:
            item: Item to put in queue
            block: Whether to block if queue is full
            timeout: Timeout for blocking operation
            
        Returns:
            True if item was added successfully
        """
        with self._not_full:
            if self.maxsize <= 0:
                # Unlimited queue
                self._queue.append(item)
                self._not_empty.notify()
                return True
                
            # Check if queue is full
            if len(self._queue) >= self.maxsize:
                if not block:
                    return self._handle_full_queue(item)
                    
                # Wait for space or timeout
                if timeout is None:
                    while len(self._queue) >= self.maxsize:
                        self._not_full.wait()
                else:
                    end_time = time.time() + timeout
                    while len(self._queue) >= self.maxsize:
                        remaining = end_time - time.time()
                        if remaining <= 0:
                            return self._handle_full_queue(item)
                        self._not_full.wait(remaining)
                        
            self._queue.append(item)
            self._not_empty.notify()
            return True
            
    def get(self, block: bool = True, timeout: Optional[float] = None) -> T:
        """Get an item from the queue.
        
        Args:
            block: Whether to block if queue is empty
            timeout: Timeout for blocking operation
            
        Returns:
            Item from queue
            
        Raises:
            Empty: If queue is empty and not blocking
        """
        with self._not_empty:
            if not self._queue:
                if not block:
                    raise Empty()
                    
                # Wait for item or timeout
                if timeout is None:
                    while not self._queue:
                        self._not_empty.wait()
                else:
                    end_time = time.time() + timeout
                    while not self._queue:
                        remaining = end_time - time.time()
                        if remaining <= 0:
                            raise Empty()
                        self._not_empty.wait(remaining)
                        
            item = self._queue.popleft()
            self._not_full.notify()
            return item
            
    def put_nowait(self, item: T) -> bool:
        """Put an item without blocking.
        
        Args:
            item: Item to put in queue
            
        Returns:
            True if item was added successfully
        """
        return self.put(item, block=False)
        
    def get_nowait(self) -> T:
        """Get an item without blocking.
        
        Returns:
            Item from queue
            
        Raises:
            Empty: If queue is empty
        """
        return self.get(block=False)
        
    def qsize(self) -> int:
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
            return len(self._queue) >= self.maxsize
            
    def clear(self) -> None:
        """Clear all items from queue."""
        with self._lock:
            self._queue.clear()
            self._not_full.notify_all()
            
    def get_dropped_count(self) -> int:
        """Get number of dropped items."""
        with self._lock:
            return self._dropped_count
            
    def _handle_full_queue(self, item: T) -> bool:
        """Handle queue full condition based on drop policy."""
        if self.drop_policy == 'oldest':
            # Drop oldest item and add new one
            self._queue.popleft()
            self._queue.append(item)
            self._dropped_count += 1
            return True
        elif self.drop_policy == 'newest':
            # Drop new item
            self._dropped_count += 1
            return False
        elif self.drop_policy == 'random':
            # Drop random item (simplified to oldest for performance)
            self._queue.popleft()
            self._queue.append(item)
            self._dropped_count += 1
            return True
        else:
            # Default: drop new item
            self._dropped_count += 1
            return False


class MemoryManager:
    """Memory management and monitoring utilities."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize memory manager.
        
        Args:
            config: Memory management configuration
        """
        self.config = config or {}
        self.memory_limit_mb = self.config.get('memory_limit_mb', 512)
        self.gc_threshold = self.config.get('gc_threshold', 0.8)
        self.monitoring_interval = self.config.get('monitoring_interval', 30)
        self.callbacks = []
        self._monitoring_thread = None
        self._stop_monitoring = threading.Event()
        
    def start_monitoring(self) -> None:
        """Start memory monitoring thread."""
        if self._monitoring_thread and self._monitoring_thread.is_alive():
            return
            
        self._stop_monitoring.clear()
        self._monitoring_thread = threading.Thread(target=self._monitor_memory, daemon=True)
        self._monitoring_thread.start()
        logger.info("Started memory monitoring")
        
    def stop_monitoring(self) -> None:
        """Stop memory monitoring thread."""
        if self._monitoring_thread:
            self._stop_monitoring.set()
            self._monitoring_thread.join(timeout=5)
            logger.info("Stopped memory monitoring")
            
    def get_memory_usage(self) -> Dict[str, float]:
        """Get current memory usage information.
        
        Returns:
            Dictionary with memory usage statistics
        """
        try:
            process = psutil.Process()
            memory_info = process.memory_info()
            
            return {
                'rss_mb': memory_info.rss / 1024 / 1024,
                'vms_mb': memory_info.vms / 1024 / 1024,
                'percent': process.memory_percent(),
                'available_mb': psutil.virtual_memory().available / 1024 / 1024,
                'total_mb': psutil.virtual_memory().total / 1024 / 1024
            }
        except Exception as e:
            logger.error(f"Failed to get memory usage: {e}")
            return {}
            
    def check_memory_pressure(self) -> bool:
        """Check if system is under memory pressure.
        
        Returns:
            True if memory pressure is detected
        """
        try:
            usage = self.get_memory_usage()
            
            # Check if RSS exceeds configured limit
            if usage.get('rss_mb', 0) > self.memory_limit_mb:
                return True
                
            # Check if memory percentage exceeds threshold
            if usage.get('percent', 0) > self.gc_threshold * 100:
                return True
                
            # Check system-wide memory availability
            if usage.get('available_mb', float('inf')) < 100:  # Less than 100MB available
                return True
                
            return False
            
        except Exception as e:
            logger.error(f"Failed to check memory pressure: {e}")
            return False
            
    def force_garbage_collection(self) -> Dict[str, int]:
        """Force garbage collection and return statistics.
        
        Returns:
            Dictionary with GC statistics
        """
        try:
            # Get pre-GC memory usage
            pre_usage = self.get_memory_usage()
            
            # Force garbage collection
            collected = gc.collect()
            
            # Get post-GC memory usage
            post_usage = self.get_memory_usage()
            
            stats = {
                'objects_collected': collected,
                'memory_freed_mb': pre_usage.get('rss_mb', 0) - post_usage.get('rss_mb', 0),
                'pre_gc_rss_mb': pre_usage.get('rss_mb', 0),
                'post_gc_rss_mb': post_usage.get('rss_mb', 0)
            }
            
            logger.info(f"Garbage collection freed {stats['memory_freed_mb']:.2f} MB")
            return stats
            
        except Exception as e:
            logger.error(f"Failed to perform garbage collection: {e}")
            return {}
            
    def set_memory_limit(self, limit_mb: int) -> bool:
        """Set memory limit for the process.
        
        Args:
            limit_mb: Memory limit in megabytes
            
        Returns:
            True if limit was set successfully
        """
        try:
            import resource
            
            # Set memory limit (RSS)
            limit_bytes = limit_mb * 1024 * 1024
            resource.setrlimit(resource.RLIMIT_RSS, (limit_bytes, limit_bytes))
            
            self.memory_limit_mb = limit_mb
            logger.info(f"Set memory limit to {limit_mb} MB")
            return True
            
        except Exception as e:
            logger.error(f"Failed to set memory limit: {e}")
            return False
            
    def register_callback(self, callback: Callable[[Dict[str, float]], None]) -> None:
        """Register callback for memory events.
        
        Args:
            callback: Function to call when memory events occur
        """
        self.callbacks.append(callback)
        
    def create_bounded_queue(self, maxsize: int, drop_policy: str = 'oldest') -> BoundedQueue:
        """Create a bounded queue with memory management.
        
        Args:
            maxsize: Maximum queue size
            drop_policy: Policy for dropping items when full
            
        Returns:
            BoundedQueue instance
        """
        return BoundedQueue(maxsize, drop_policy)
        
    def get_object_counts(self) -> Dict[str, int]:
        """Get counts of objects by type.
        
        Returns:
            Dictionary mapping object types to counts
        """
        try:
            import gc
            
            type_counts = {}
            for obj in gc.get_objects():
                obj_type = type(obj).__name__
                type_counts[obj_type] = type_counts.get(obj_type, 0) + 1
                
            # Sort by count and return top 20
            sorted_counts = sorted(type_counts.items(), key=lambda x: x[1], reverse=True)
            return dict(sorted_counts[:20])
            
        except Exception as e:
            logger.error(f"Failed to get object counts: {e}")
            return {}
            
    def find_memory_leaks(self) -> List[Dict[str, Any]]:
        """Find potential memory leaks.
        
        Returns:
            List of potential leak information
        """
        try:
            import gc
            
            leaks = []
            
            # Find objects with reference cycles
            for obj in gc.garbage:
                leak_info = {
                    'type': type(obj).__name__,
                    'id': id(obj),
                    'referrers': len(gc.get_referrers(obj)),
                    'referents': len(gc.get_referents(obj))
                }
                leaks.append(leak_info)
                
            return leaks
            
        except Exception as e:
            logger.error(f"Failed to find memory leaks: {e}")
            return []
            
    def _monitor_memory(self) -> None:
        """Memory monitoring thread function."""
        while not self._stop_monitoring.wait(self.monitoring_interval):
            try:
                usage = self.get_memory_usage()
                
                # Check for memory pressure
                if self.check_memory_pressure():
                    logger.warning(f"Memory pressure detected: {usage}")
                    
                    # Force garbage collection
                    gc_stats = self.force_garbage_collection()
                    
                    # Notify callbacks
                    for callback in self.callbacks:
                        try:
                            callback(usage)
                        except Exception as e:
                            logger.error(f"Memory callback error: {e}")
                            
                # Log memory usage periodically
                if logger.isEnabledFor(logging.DEBUG):
                    logger.debug(f"Memory usage: {usage}")
                    
            except Exception as e:
                logger.error(f"Memory monitoring error: {e}")


class MemoryPool:
    """Memory pool for object reuse."""
    
    def __init__(self, factory: Callable[[], T], max_size: int = 100):
        """Initialize memory pool.
        
        Args:
            factory: Function to create new objects
            max_size: Maximum pool size
        """
        self.factory = factory
        self.max_size = max_size
        self._pool = deque()
        self._lock = threading.Lock()
        
    def get(self) -> T:
        """Get an object from the pool.
        
        Returns:
            Object from pool or newly created
        """
        with self._lock:
            if self._pool:
                return self._pool.popleft()
            else:
                return self.factory()
                
    def put(self, obj: T) -> None:
        """Return an object to the pool.
        
        Args:
            obj: Object to return to pool
        """
        with self._lock:
            if len(self._pool) < self.max_size:
                # Reset object state if it has a reset method
                if hasattr(obj, 'reset'):
                    obj.reset()
                self._pool.append(obj)
                
    def clear(self) -> None:
        """Clear all objects from pool."""
        with self._lock:
            self._pool.clear()
            
    def size(self) -> int:
        """Get current pool size."""
        with self._lock:
            return len(self._pool)