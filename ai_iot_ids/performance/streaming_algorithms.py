"""Streaming algorithms for constant memory usage."""

import logging
import math
import random
import hashlib
from typing import Any, Dict, List, Optional, Union, Iterator, Callable
from collections import defaultdict, deque
import heapq
import time

logger = logging.getLogger(__name__)


class StreamingProcessor:
    """Base class for streaming data processors."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize streaming processor.
        
        Args:
            config: Processor configuration
        """
        self.config = config or {}
        self.processed_count = 0
        self.start_time = time.time()
        
    def process(self, item: Any) -> Optional[Any]:
        """Process a single item.
        
        Args:
            item: Item to process
            
        Returns:
            Processed result or None
        """
        self.processed_count += 1
        return self._process_item(item)
        
    def _process_item(self, item: Any) -> Optional[Any]:
        """Override this method in subclasses."""
        raise NotImplementedError
        
    def get_statistics(self) -> Dict[str, Any]:
        """Get processing statistics."""
        elapsed = time.time() - self.start_time
        return {
            'processed_count': self.processed_count,
            'elapsed_seconds': elapsed,
            'items_per_second': self.processed_count / elapsed if elapsed > 0 else 0
        }


class CountMinSketch:
    """Count-Min Sketch for approximate frequency counting."""
    
    def __init__(self, width: int = 1000, depth: int = 5):
        """Initialize Count-Min Sketch.
        
        Args:
            width: Width of the sketch (number of buckets)
            depth: Depth of the sketch (number of hash functions)
        """
        self.width = width
        self.depth = depth
        self.table = [[0] * width for _ in range(depth)]
        self.hash_functions = self._generate_hash_functions()
        
    def add(self, item: str, count: int = 1) -> None:
        """Add an item to the sketch.
        
        Args:
            item: Item to add
            count: Count to add (default 1)
        """
        for i, hash_func in enumerate(self.hash_functions):
            bucket = hash_func(item) % self.width
            self.table[i][bucket] += count
            
    def estimate(self, item: str) -> int:
        """Estimate the count of an item.
        
        Args:
            item: Item to estimate
            
        Returns:
            Estimated count
        """
        estimates = []
        for i, hash_func in enumerate(self.hash_functions):
            bucket = hash_func(item) % self.width
            estimates.append(self.table[i][bucket])
        return min(estimates)
        
    def _generate_hash_functions(self) -> List[Callable[[str], int]]:
        """Generate hash functions for the sketch."""
        hash_functions = []
        for i in range(self.depth):
            # Use different seeds for each hash function
            seed = i * 1000 + 42
            hash_functions.append(lambda x, s=seed: hash((x, s)) & 0x7fffffff)
        return hash_functions


class HyperLogLog:
    """HyperLogLog for approximate cardinality estimation."""
    
    def __init__(self, precision: int = 12):
        """Initialize HyperLogLog.
        
        Args:
            precision: Precision parameter (4-16)
        """
        self.precision = max(4, min(16, precision))
        self.m = 1 << self.precision  # 2^precision
        self.buckets = [0] * self.m
        self.alpha = self._get_alpha()
        
    def add(self, item: str) -> None:
        """Add an item to the estimator.
        
        Args:
            item: Item to add
        """
        # Hash the item
        hash_value = int(hashlib.md5(item.encode()).hexdigest(), 16)
        
        # Get bucket index from first p bits
        bucket = hash_value & (self.m - 1)
        
        # Get leading zeros from remaining bits
        w = hash_value >> self.precision
        leading_zeros = self._leading_zeros(w) + 1
        
        # Update bucket with maximum leading zeros seen
        self.buckets[bucket] = max(self.buckets[bucket], leading_zeros)
        
    def estimate(self) -> int:
        """Estimate the cardinality.
        
        Returns:
            Estimated cardinality
        """
        # Calculate raw estimate
        raw_estimate = self.alpha * (self.m ** 2) / sum(2 ** (-x) for x in self.buckets)
        
        # Apply small range correction
        if raw_estimate <= 2.5 * self.m:
            zeros = self.buckets.count(0)
            if zeros != 0:
                return int(self.m * math.log(self.m / zeros))
                
        # Apply large range correction
        if raw_estimate <= (1.0/30.0) * (1 << 32):
            return int(raw_estimate)
        else:
            return int(-1 * (1 << 32) * math.log(1 - raw_estimate / (1 << 32)))
            
    def _get_alpha(self) -> float:
        """Get alpha constant for bias correction."""
        if self.m == 16:
            return 0.673
        elif self.m == 32:
            return 0.697
        elif self.m == 64:
            return 0.709
        else:
            return 0.7213 / (1 + 1.079 / self.m)
            
    def _leading_zeros(self, w: int) -> int:
        """Count leading zeros in binary representation."""
        if w == 0:
            return 32
        return (w ^ (w - 1)).bit_length() - 1


class ReservoirSampler:
    """Reservoir sampling for uniform random sampling from streams."""
    
    def __init__(self, sample_size: int):
        """Initialize reservoir sampler.
        
        Args:
            sample_size: Size of the sample to maintain
        """
        self.sample_size = sample_size
        self.reservoir = []
        self.count = 0
        
    def add(self, item: Any) -> None:
        """Add an item to the reservoir.
        
        Args:
            item: Item to add
        """
        self.count += 1
        
        if len(self.reservoir) < self.sample_size:
            # Reservoir not full, add item
            self.reservoir.append(item)
        else:
            # Reservoir full, replace with probability k/n
            j = random.randint(0, self.count - 1)
            if j < self.sample_size:
                self.reservoir[j] = item
                
    def get_sample(self) -> List[Any]:
        """Get the current sample.
        
        Returns:
            List of sampled items
        """
        return self.reservoir.copy()
        
    def get_sample_size(self) -> int:
        """Get current sample size."""
        return len(self.reservoir)


class BloomFilter:
    """Bloom filter for approximate set membership testing."""
    
    def __init__(self, capacity: int, error_rate: float = 0.01):
        """Initialize Bloom filter.
        
        Args:
            capacity: Expected number of items
            error_rate: Desired false positive rate
        """
        self.capacity = capacity
        self.error_rate = error_rate
        
        # Calculate optimal parameters
        self.bit_array_size = int(-capacity * math.log(error_rate) / (math.log(2) ** 2))
        self.hash_count = int(self.bit_array_size * math.log(2) / capacity)
        
        # Initialize bit array
        self.bit_array = [False] * self.bit_array_size
        self.item_count = 0
        
    def add(self, item: str) -> None:
        """Add an item to the filter.
        
        Args:
            item: Item to add
        """
        for i in range(self.hash_count):
            hash_value = hash((item, i)) % self.bit_array_size
            self.bit_array[hash_value] = True
        self.item_count += 1
        
    def contains(self, item: str) -> bool:
        """Check if an item might be in the set.
        
        Args:
            item: Item to check
            
        Returns:
            True if item might be in set, False if definitely not
        """
        for i in range(self.hash_count):
            hash_value = hash((item, i)) % self.bit_array_size
            if not self.bit_array[hash_value]:
                return False
        return True
        
    def get_false_positive_rate(self) -> float:
        """Get current false positive rate estimate."""
        if self.item_count == 0:
            return 0.0
        return (1 - math.exp(-self.hash_count * self.item_count / self.bit_array_size)) ** self.hash_count


class TopKTracker:
    """Track top-K most frequent items in a stream."""
    
    def __init__(self, k: int):
        """Initialize top-K tracker.
        
        Args:
            k: Number of top items to track
        """
        self.k = k
        self.counts = defaultdict(int)
        self.heap = []  # Min-heap of (count, item)
        
    def add(self, item: str) -> None:
        """Add an item to the tracker.
        
        Args:
            item: Item to add
        """
        self.counts[item] += 1
        count = self.counts[item]
        
        # Check if item is already in heap
        item_in_heap = any(item == heap_item for _, heap_item in self.heap)
        
        if item_in_heap:
            # Update heap (rebuild for simplicity)
            self._rebuild_heap()
        elif len(self.heap) < self.k:
            # Heap not full, add item
            heapq.heappush(self.heap, (count, item))
        elif count > self.heap[0][0]:
            # Item has higher count than minimum in heap
            heapq.heapreplace(self.heap, (count, item))
            
    def get_top_k(self) -> List[tuple]:
        """Get top-K items.
        
        Returns:
            List of (count, item) tuples sorted by count descending
        """
        return sorted(self.heap, reverse=True)
        
    def _rebuild_heap(self) -> None:
        """Rebuild heap with current counts."""
        # Get top-K items by count
        top_items = sorted(self.counts.items(), key=lambda x: x[1], reverse=True)[:self.k]
        self.heap = [(count, item) for item, count in top_items]
        heapq.heapify(self.heap)


class SlidingWindowCounter:
    """Count items in a sliding time window."""
    
    def __init__(self, window_size_seconds: int):
        """Initialize sliding window counter.
        
        Args:
            window_size_seconds: Size of the sliding window in seconds
        """
        self.window_size = window_size_seconds
        self.events = deque()  # (timestamp, item)
        self.counts = defaultdict(int)
        
    def add(self, item: str, timestamp: Optional[float] = None) -> None:
        """Add an item to the window.
        
        Args:
            item: Item to add
            timestamp: Event timestamp (default: current time)
        """
        if timestamp is None:
            timestamp = time.time()
            
        # Add new event
        self.events.append((timestamp, item))
        self.counts[item] += 1
        
        # Remove old events outside window
        self._cleanup_old_events(timestamp)
        
    def get_count(self, item: str) -> int:
        """Get count of an item in current window.
        
        Args:
            item: Item to count
            
        Returns:
            Count of item in window
        """
        self._cleanup_old_events()
        return self.counts[item]
        
    def get_all_counts(self) -> Dict[str, int]:
        """Get counts of all items in current window.
        
        Returns:
            Dictionary mapping items to counts
        """
        self._cleanup_old_events()
        return dict(self.counts)
        
    def _cleanup_old_events(self, current_time: Optional[float] = None) -> None:
        """Remove events outside the sliding window."""
        if current_time is None:
            current_time = time.time()
            
        cutoff_time = current_time - self.window_size
        
        while self.events and self.events[0][0] < cutoff_time:
            _, item = self.events.popleft()
            self.counts[item] -= 1
            if self.counts[item] == 0:
                del self.counts[item]


class StreamingStatistics:
    """Compute streaming statistics with constant memory."""
    
    def __init__(self):
        """Initialize streaming statistics."""
        self.count = 0
        self.sum = 0.0
        self.sum_squares = 0.0
        self.min_value = float('inf')
        self.max_value = float('-inf')
        
    def add(self, value: float) -> None:
        """Add a value to the statistics.
        
        Args:
            value: Value to add
        """
        self.count += 1
        self.sum += value
        self.sum_squares += value * value
        self.min_value = min(self.min_value, value)
        self.max_value = max(self.max_value, value)
        
    def get_mean(self) -> float:
        """Get the mean value."""
        return self.sum / self.count if self.count > 0 else 0.0
        
    def get_variance(self) -> float:
        """Get the variance."""
        if self.count < 2:
            return 0.0
        mean = self.get_mean()
        return (self.sum_squares - self.count * mean * mean) / (self.count - 1)
        
    def get_std_dev(self) -> float:
        """Get the standard deviation."""
        return math.sqrt(self.get_variance())
        
    def get_statistics(self) -> Dict[str, float]:
        """Get all statistics.
        
        Returns:
            Dictionary with all computed statistics
        """
        return {
            'count': self.count,
            'sum': self.sum,
            'mean': self.get_mean(),
            'variance': self.get_variance(),
            'std_dev': self.get_std_dev(),
            'min': self.min_value if self.count > 0 else 0.0,
            'max': self.max_value if self.count > 0 else 0.0
        }