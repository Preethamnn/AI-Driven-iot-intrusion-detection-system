"""Data compression and sampling strategies."""

import logging
import gzip
import lz4.frame
import zlib
import bz2
import random
import time
import json
from typing import Any, Dict, List, Optional, Union, Callable, Iterator
from io import BytesIO
import pickle
import struct

logger = logging.getLogger(__name__)


class CompressionManager:
    """Manages data compression with multiple algorithms."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize compression manager.
        
        Args:
            config: Compression configuration
        """
        self.config = config or {}
        self.default_algorithm = self.config.get('default_algorithm', 'gzip')
        self.compression_level = self.config.get('compression_level', 6)
        self.min_size_threshold = self.config.get('min_size_threshold', 1024)  # Don't compress small data
        
        # Available compression algorithms
        self.algorithms = {
            'gzip': {
                'compress': self._gzip_compress,
                'decompress': self._gzip_decompress,
                'extension': '.gz'
            },
            'lz4': {
                'compress': self._lz4_compress,
                'decompress': self._lz4_decompress,
                'extension': '.lz4'
            },
            'zlib': {
                'compress': self._zlib_compress,
                'decompress': self._zlib_decompress,
                'extension': '.zlib'
            },
            'bz2': {
                'compress': self._bz2_compress,
                'decompress': self._bz2_decompress,
                'extension': '.bz2'
            }
        }
        
    def compress(self, data: bytes, algorithm: Optional[str] = None) -> Dict[str, Any]:
        """Compress data using specified algorithm.
        
        Args:
            data: Data to compress
            algorithm: Compression algorithm to use
            
        Returns:
            Dictionary with compressed data and metadata
        """
        algorithm = algorithm or self.default_algorithm
        
        if algorithm not in self.algorithms:
            raise ValueError(f"Unsupported compression algorithm: {algorithm}")
            
        # Skip compression for small data
        if len(data) < self.min_size_threshold:
            return {
                'data': data,
                'algorithm': 'none',
                'original_size': len(data),
                'compressed_size': len(data),
                'compression_ratio': 1.0,
                'compression_time': 0.0
            }
            
        start_time = time.time()
        
        try:
            compress_func = self.algorithms[algorithm]['compress']
            compressed_data = compress_func(data)
            
            compression_time = time.time() - start_time
            compression_ratio = len(data) / len(compressed_data) if compressed_data else 1.0
            
            return {
                'data': compressed_data,
                'algorithm': algorithm,
                'original_size': len(data),
                'compressed_size': len(compressed_data),
                'compression_ratio': compression_ratio,
                'compression_time': compression_time
            }
            
        except Exception as e:
            logger.error(f"Compression failed with {algorithm}: {e}")
            # Return uncompressed data as fallback
            return {
                'data': data,
                'algorithm': 'none',
                'original_size': len(data),
                'compressed_size': len(data),
                'compression_ratio': 1.0,
                'compression_time': 0.0,
                'error': str(e)
            }
            
    def decompress(self, compressed_data: bytes, algorithm: str) -> bytes:
        """Decompress data using specified algorithm.
        
        Args:
            compressed_data: Compressed data
            algorithm: Algorithm used for compression
            
        Returns:
            Decompressed data
        """
        if algorithm == 'none':
            return compressed_data
            
        if algorithm not in self.algorithms:
            raise ValueError(f"Unsupported compression algorithm: {algorithm}")
            
        try:
            decompress_func = self.algorithms[algorithm]['decompress']
            return decompress_func(compressed_data)
            
        except Exception as e:
            logger.error(f"Decompression failed with {algorithm}: {e}")
            raise
            
    def benchmark_algorithms(self, test_data: bytes) -> Dict[str, Dict[str, float]]:
        """Benchmark compression algorithms on test data.
        
        Args:
            test_data: Data to use for benchmarking
            
        Returns:
            Dictionary with benchmark results for each algorithm
        """
        results = {}
        
        for algorithm in self.algorithms.keys():
            try:
                # Compress
                result = self.compress(test_data, algorithm)
                
                # Decompress to verify
                decompressed = self.decompress(result['data'], algorithm)
                
                # Verify data integrity
                if decompressed != test_data:
                    logger.error(f"Data integrity check failed for {algorithm}")
                    continue
                    
                results[algorithm] = {
                    'compression_ratio': result['compression_ratio'],
                    'compression_time': result['compression_time'],
                    'compressed_size': result['compressed_size'],
                    'original_size': result['original_size']
                }
                
            except Exception as e:
                logger.error(f"Benchmark failed for {algorithm}: {e}")
                
        return results
        
    def choose_best_algorithm(self, test_data: bytes, 
                            priority: str = 'ratio') -> str:
        """Choose the best compression algorithm based on criteria.
        
        Args:
            test_data: Data to test algorithms on
            priority: Optimization priority ('ratio', 'speed', 'balanced')
            
        Returns:
            Name of the best algorithm
        """
        results = self.benchmark_algorithms(test_data)
        
        if not results:
            return self.default_algorithm
            
        if priority == 'ratio':
            # Choose algorithm with best compression ratio
            best = max(results.items(), key=lambda x: x[1]['compression_ratio'])
        elif priority == 'speed':
            # Choose algorithm with fastest compression
            best = min(results.items(), key=lambda x: x[1]['compression_time'])
        elif priority == 'balanced':
            # Choose algorithm with best ratio/time balance
            best = max(results.items(), 
                      key=lambda x: x[1]['compression_ratio'] / (x[1]['compression_time'] + 0.001))
        else:
            return self.default_algorithm
            
        return best[0]
        
    def _gzip_compress(self, data: bytes) -> bytes:
        """Compress data using gzip."""
        return gzip.compress(data, compresslevel=self.compression_level)
        
    def _gzip_decompress(self, data: bytes) -> bytes:
        """Decompress gzip data."""
        return gzip.decompress(data)
        
    def _lz4_compress(self, data: bytes) -> bytes:
        """Compress data using LZ4."""
        try:
            return lz4.frame.compress(data, compression_level=self.compression_level)
        except ImportError:
            raise ValueError("LZ4 not available")
            
    def _lz4_decompress(self, data: bytes) -> bytes:
        """Decompress LZ4 data."""
        try:
            return lz4.frame.decompress(data)
        except ImportError:
            raise ValueError("LZ4 not available")
            
    def _zlib_compress(self, data: bytes) -> bytes:
        """Compress data using zlib."""
        return zlib.compress(data, level=self.compression_level)
        
    def _zlib_decompress(self, data: bytes) -> bytes:
        """Decompress zlib data."""
        return zlib.decompress(data)
        
    def _bz2_compress(self, data: bytes) -> bytes:
        """Compress data using bz2."""
        return bz2.compress(data, compresslevel=self.compression_level)
        
    def _bz2_decompress(self, data: bytes) -> bytes:
        """Decompress bz2 data."""
        return bz2.decompress(data)


class SamplingManager:
    """Manages data sampling strategies."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize sampling manager.
        
        Args:
            config: Sampling configuration
        """
        self.config = config or {}
        self.default_rate = self.config.get('default_rate', 0.1)
        self.adaptive_sampling = self.config.get('adaptive_sampling', True)
        self.min_rate = self.config.get('min_rate', 0.01)
        self.max_rate = self.config.get('max_rate', 1.0)
        
        # Sampling state
        self.current_rate = self.default_rate
        self.sample_count = 0
        self.total_count = 0
        self.last_adjustment = time.time()
        
    def should_sample(self, item: Any = None, 
                     priority: Optional[float] = None) -> bool:
        """Determine if an item should be sampled.
        
        Args:
            item: Item to potentially sample
            priority: Priority score for the item (0-1)
            
        Returns:
            True if item should be sampled
        """
        self.total_count += 1
        
        # Priority-based sampling
        if priority is not None:
            # Higher priority items are more likely to be sampled
            threshold = self.current_rate * (1 + priority)
            should_sample = random.random() < min(threshold, 1.0)
        else:
            # Simple random sampling
            should_sample = random.random() < self.current_rate
            
        if should_sample:
            self.sample_count += 1
            
        # Adjust sampling rate if adaptive sampling is enabled
        if self.adaptive_sampling:
            self._adjust_sampling_rate()
            
        return should_sample
        
    def systematic_sample(self, items: List[Any], 
                         sample_size: int) -> List[Any]:
        """Perform systematic sampling on a list of items.
        
        Args:
            items: List of items to sample from
            sample_size: Number of items to sample
            
        Returns:
            List of sampled items
        """
        if sample_size >= len(items):
            return items.copy()
            
        if sample_size <= 0:
            return []
            
        # Calculate sampling interval
        interval = len(items) / sample_size
        
        # Random starting point
        start = random.uniform(0, interval)
        
        sampled_items = []
        for i in range(sample_size):
            index = int(start + i * interval)
            if index < len(items):
                sampled_items.append(items[index])
                
        return sampled_items
        
    def stratified_sample(self, items: List[Any], 
                         sample_size: int,
                         strata_func: Callable[[Any], str]) -> List[Any]:
        """Perform stratified sampling on a list of items.
        
        Args:
            items: List of items to sample from
            sample_size: Total number of items to sample
            strata_func: Function to determine stratum for each item
            
        Returns:
            List of sampled items
        """
        if sample_size >= len(items):
            return items.copy()
            
        # Group items by strata
        strata = {}
        for item in items:
            stratum = strata_func(item)
            if stratum not in strata:
                strata[stratum] = []
            strata[stratum].append(item)
            
        # Calculate sample size per stratum
        sampled_items = []
        total_strata = len(strata)
        
        for stratum, stratum_items in strata.items():
            # Proportional allocation
            stratum_sample_size = int(sample_size * len(stratum_items) / len(items))
            
            # Ensure at least one item per stratum if possible
            if stratum_sample_size == 0 and len(stratum_items) > 0:
                stratum_sample_size = 1
                
            # Random sample from stratum
            if stratum_sample_size > 0:
                sampled_items.extend(
                    random.sample(stratum_items, 
                                min(stratum_sample_size, len(stratum_items)))
                )
                
        return sampled_items
        
    def reservoir_sample(self, items: Iterator[Any], 
                        sample_size: int) -> List[Any]:
        """Perform reservoir sampling on a stream of items.
        
        Args:
            items: Iterator of items to sample from
            sample_size: Size of the reservoir
            
        Returns:
            List of sampled items
        """
        reservoir = []
        count = 0
        
        for item in items:
            count += 1
            
            if len(reservoir) < sample_size:
                reservoir.append(item)
            else:
                # Replace with probability k/n
                j = random.randint(0, count - 1)
                if j < sample_size:
                    reservoir[j] = item
                    
        return reservoir
        
    def time_based_sample(self, items: List[tuple], 
                         sample_size: int,
                         time_window: float) -> List[tuple]:
        """Sample items based on time distribution.
        
        Args:
            items: List of (timestamp, item) tuples
            sample_size: Number of items to sample
            time_window: Time window to consider (seconds)
            
        Returns:
            List of sampled (timestamp, item) tuples
        """
        if not items:
            return []
            
        # Sort items by timestamp
        sorted_items = sorted(items, key=lambda x: x[0])
        
        # Filter items within time window
        current_time = time.time()
        cutoff_time = current_time - time_window
        recent_items = [item for item in sorted_items if item[0] >= cutoff_time]
        
        if len(recent_items) <= sample_size:
            return recent_items
            
        # Sample uniformly across time window
        return self.systematic_sample(recent_items, sample_size)
        
    def adaptive_sample_rate(self, load_factor: float) -> float:
        """Calculate adaptive sampling rate based on system load.
        
        Args:
            load_factor: System load factor (0-1)
            
        Returns:
            Adjusted sampling rate
        """
        # Decrease sampling rate as load increases
        if load_factor > 0.8:
            # High load: reduce sampling significantly
            adjusted_rate = self.current_rate * 0.5
        elif load_factor > 0.6:
            # Medium load: reduce sampling moderately
            adjusted_rate = self.current_rate * 0.7
        elif load_factor < 0.3:
            # Low load: increase sampling
            adjusted_rate = self.current_rate * 1.2
        else:
            # Normal load: maintain current rate
            adjusted_rate = self.current_rate
            
        # Clamp to configured bounds
        return max(self.min_rate, min(self.max_rate, adjusted_rate))
        
    def get_sampling_statistics(self) -> Dict[str, Any]:
        """Get sampling statistics.
        
        Returns:
            Dictionary with sampling statistics
        """
        return {
            'current_rate': self.current_rate,
            'sample_count': self.sample_count,
            'total_count': self.total_count,
            'actual_rate': self.sample_count / self.total_count if self.total_count > 0 else 0.0,
            'last_adjustment': self.last_adjustment
        }
        
    def reset_statistics(self) -> None:
        """Reset sampling statistics."""
        self.sample_count = 0
        self.total_count = 0
        self.last_adjustment = time.time()
        
    def _adjust_sampling_rate(self) -> None:
        """Adjust sampling rate based on recent performance."""
        current_time = time.time()
        
        # Only adjust every 60 seconds
        if current_time - self.last_adjustment < 60:
            return
            
        if self.total_count > 0:
            actual_rate = self.sample_count / self.total_count
            
            # If actual rate deviates significantly from target, adjust
            if abs(actual_rate - self.current_rate) > 0.05:
                # Gradually adjust towards target
                adjustment = (self.current_rate - actual_rate) * 0.1
                self.current_rate = max(self.min_rate, 
                                      min(self.max_rate, 
                                          self.current_rate + adjustment))
                                          
        self.last_adjustment = current_time


class DataCompressor:
    """High-level data compression interface."""
    
    def __init__(self, compression_manager: CompressionManager,
                 sampling_manager: SamplingManager):
        """Initialize data compressor.
        
        Args:
            compression_manager: Compression manager instance
            sampling_manager: Sampling manager instance
        """
        self.compression_manager = compression_manager
        self.sampling_manager = sampling_manager
        
    def compress_and_sample(self, data: List[Dict[str, Any]], 
                           sample_rate: Optional[float] = None,
                           compression_algorithm: Optional[str] = None) -> Dict[str, Any]:
        """Compress and sample data in one operation.
        
        Args:
            data: List of data items to process
            sample_rate: Sampling rate to use
            compression_algorithm: Compression algorithm to use
            
        Returns:
            Dictionary with processed data and metadata
        """
        # Sample data first
        if sample_rate:
            original_rate = self.sampling_manager.current_rate
            self.sampling_manager.current_rate = sample_rate
            
        sampled_data = []
        for item in data:
            if self.sampling_manager.should_sample(item):
                sampled_data.append(item)
                
        # Restore original sampling rate
        if sample_rate:
            self.sampling_manager.current_rate = original_rate
            
        # Serialize sampled data
        serialized_data = json.dumps(sampled_data).encode('utf-8')
        
        # Compress serialized data
        compression_result = self.compression_manager.compress(
            serialized_data, compression_algorithm
        )
        
        return {
            'compressed_data': compression_result['data'],
            'compression_metadata': {
                'algorithm': compression_result['algorithm'],
                'original_size': len(serialized_data),
                'compressed_size': compression_result['compressed_size'],
                'compression_ratio': compression_result['compression_ratio']
            },
            'sampling_metadata': {
                'original_count': len(data),
                'sampled_count': len(sampled_data),
                'sampling_rate': len(sampled_data) / len(data) if data else 0.0
            }
        }
        
    def decompress_data(self, compressed_data: bytes, 
                       algorithm: str) -> List[Dict[str, Any]]:
        """Decompress data.
        
        Args:
            compressed_data: Compressed data
            algorithm: Compression algorithm used
            
        Returns:
            List of decompressed data items
        """
        # Decompress data
        decompressed_data = self.compression_manager.decompress(
            compressed_data, algorithm
        )
        
        # Deserialize data
        return json.loads(decompressed_data.decode('utf-8'))