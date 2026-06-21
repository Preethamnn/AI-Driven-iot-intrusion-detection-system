"""
Network Flow Feature Extractor implementation for the AI-driven IoT IDS system.

This module provides a concrete implementation of the FeatureExtractorInterface
that extracts flow-level features, directional metrics, and protocol-specific
features from network traffic metadata.
"""

import math
import statistics
from collections import defaultdict, Counter
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Set
from urllib.parse import urlparse
import hashlib
import re

from ..interfaces.feature_extractor import (
    FeatureExtractorInterface, 
    FeatureVector, 
    FlowWindow
)
from ..interfaces.protocol_decoder import ProtocolMetadata, ProtocolType
from ..models.network_flow import NetworkFlow


class NetworkFlowExtractor(FeatureExtractorInterface):
    """
    Concrete implementation of feature extraction for network flow analysis.
    
    Extracts flow-level features, timing statistics, directional metrics,
    and protocol-specific features for ML-based threat detection.
    """
    
    def __init__(self, config: Dict[str, Any], logger=None):
        """
        Initialize the network flow feature extractor.
        
        Args:
            config: Configuration dictionary containing extraction parameters
            logger: Optional logger instance
        """
        super().__init__(config, logger)
        
        # Feature extraction configuration
        self.time_window_minutes = config.get('time_window_minutes', 5)
        self.max_flows_per_window = config.get('max_flows_per_window', 10000)
        self.enable_dns_features = config.get('enable_dns_features', True)
        self.enable_tls_features = config.get('enable_tls_features', True)
        
        # Statistics tracking
        self.flows_processed = 0
        self.features_extracted = 0
        self.processing_start_time = None
        
        # Feature importance weights (can be learned from ML models)
        self.feature_importance = {
            'bytes_per_packet': 0.15,
            'duration_seconds': 0.12,
            'inter_arrival_mean': 0.10,
            'port_entropy': 0.08,
            'fan_out_ratio': 0.07,
            'protocol_diversity': 0.06,
            'dns_entropy': 0.05,
            'tls_ja3_present': 0.04
        }
    
    async def initialize(self) -> None:
        """Initialize the feature extractor."""
        self.processing_start_time = datetime.utcnow()
        self._initialized = True
        self.log_info("NetworkFlowExtractor initialized")
    
    async def start(self) -> None:
        """Start the feature extractor."""
        if not self._initialized:
            await self.initialize()
        self._running = True
        self.log_info("NetworkFlowExtractor started")
    
    async def stop(self) -> None:
        """Stop the feature extractor."""
        self._running = False
        self.log_info("NetworkFlowExtractor stopped")
    
    async def extract_flow_features(self, metadata_list: List[ProtocolMetadata]) -> NetworkFlow:
        """
        Extract network flow features from protocol metadata.
        
        Args:
            metadata_list: List of protocol metadata for the same flow
            
        Returns:
            NetworkFlow object with extracted features
        """
        if not metadata_list:
            raise ValueError("Empty metadata list provided")
        
        # Group metadata by flow (src_ip, dst_ip, src_port, dst_port, protocol)
        flow_groups = self._group_metadata_by_flow(metadata_list)
        
        if len(flow_groups) != 1:
            raise ValueError(f"Expected single flow, got {len(flow_groups)} flows")
        
        flow_key, flow_metadata = next(iter(flow_groups.items()))
        src_ip, dst_ip, src_port, dst_port, protocol = flow_key
        
        # Filter out non-IP or UNKNOWN protocols to prevent Pydantic validation errors
        protocol_str = str(protocol).upper()
        if not src_ip or not dst_ip or protocol_str not in {'TCP', 'UDP', 'ICMP', 'ICMPV6'}:
            raise ValueError(f"Skipping flow extraction for unsupported protocol '{protocol}' or missing IP")
            
        # Sort by timestamp for timing calculations
        flow_metadata.sort(key=lambda x: x.timestamp)
        
        # Calculate basic flow statistics
        total_payload = sum(m.payload_size for m in flow_metadata)
        packet_count = len(flow_metadata)
        
        # Calculate timing features
        if len(flow_metadata) > 1:
            duration_ms = int((flow_metadata[-1].timestamp - flow_metadata[0].timestamp).total_seconds() * 1000)
            inter_arrivals = []
            for i in range(1, len(flow_metadata)):
                delta = (flow_metadata[i].timestamp - flow_metadata[i-1].timestamp).total_seconds() * 1000
                inter_arrivals.append(delta)
            
            inter_arrival_mean = statistics.mean(inter_arrivals) if inter_arrivals else 0.0
            inter_arrival_std = statistics.stdev(inter_arrivals) if len(inter_arrivals) > 1 else 0.0
            jitter = inter_arrival_std  # Simplified jitter calculation
        else:
            duration_ms = 0
            inter_arrival_mean = 0.0
            inter_arrival_std = 0.0
            jitter = 0.0
        
        # Extract TCP-specific features
        tcp_flags = []
        retransmissions = 0
        if protocol.upper() == 'TCP':
            for metadata in flow_metadata:
                if metadata.tcp_flags:
                    tcp_flags.extend(metadata.tcp_flags)
            tcp_flags = list(set(tcp_flags))  # Remove duplicates
            
            # Simple retransmission detection (could be improved)
            seq_numbers = [m.tcp_sequence_number for m in flow_metadata if m.tcp_sequence_number]
            if seq_numbers:
                retransmissions = len(seq_numbers) - len(set(seq_numbers))
        
        syn_fin_ratio = 0.0
        if tcp_flags:
            syn_count = tcp_flags.count('SYN')
            fin_count = tcp_flags.count('FIN')
            syn_fin_ratio = syn_count / fin_count if fin_count > 0 else float(syn_count)
        
        # Create NetworkFlow object
        flow = NetworkFlow(
            timestamp=flow_metadata[0].timestamp,
            source_ip=src_ip,
            destination_ip=dst_ip,
            source_port=src_port,
            destination_port=dst_port,
            protocol=protocol,
            bytes_sent=total_payload,  # Simplified - assumes all traffic is outbound
            bytes_received=0,  # Would need bidirectional flow tracking
            packets_sent=packet_count,
            packets_received=0,
            duration_ms=duration_ms,
            inter_arrival_mean_ms=inter_arrival_mean,
            inter_arrival_std_ms=inter_arrival_std,
            jitter_ms=jitter,
            tcp_flags=tcp_flags,
            retransmissions=retransmissions,
            syn_fin_ratio=syn_fin_ratio,
            unique_destinations=1,  # Single destination in this flow
            fan_out_ratio=0.0,  # Will be calculated at device level
            fan_in_ratio=0.0,   # Will be calculated at device level
            port_distribution_entropy=0.0  # Will be calculated at device level
        )
        
        self.flows_processed += 1
        return flow
    
    async def extract_temporal_features(self, flows: List[NetworkFlow], 
                                      window: FlowWindow) -> FeatureVector:
        """
        Extract temporal features from multiple flows within a time window.
        
        Args:
            flows: List of network flows within the time window
            window: Time window for feature aggregation
            
        Returns:
            FeatureVector with temporal features
        """
        if not flows:
            raise ValueError("Empty flows list provided")
        
        # Filter flows within the window
        window_flows = [f for f in flows if window.contains(f.timestamp)]
        
        if not window_flows:
            raise ValueError("No flows found within the specified window")
        
        # Calculate temporal aggregation features
        features = {}
        
        # Basic statistics
        features['flow_count'] = float(len(window_flows))
        features['total_bytes'] = float(sum(f.total_bytes() for f in window_flows))
        features['total_packets'] = float(sum(f.total_packets() for f in window_flows))
        features['avg_duration'] = float(statistics.mean([f.duration_ms for f in window_flows]))
        
        # Timing features
        durations = [f.duration_ms for f in window_flows if f.duration_ms > 0]
        if durations:
            features['duration_std'] = float(statistics.stdev(durations) if len(durations) > 1 else 0.0)
            features['duration_max'] = float(max(durations))
            features['duration_min'] = float(min(durations))
        else:
            features['duration_std'] = 0.0
            features['duration_max'] = 0.0
            features['duration_min'] = 0.0
        
        # Protocol distribution
        protocols = [f.protocol for f in window_flows]
        protocol_counts = Counter(protocols)
        features['protocol_diversity'] = float(len(protocol_counts))
        features['tcp_ratio'] = float(protocol_counts.get('TCP', 0) / len(window_flows))
        features['udp_ratio'] = float(protocol_counts.get('UDP', 0) / len(window_flows))
        
        # Port analysis
        dst_ports = [f.destination_port for f in window_flows]
        features['unique_dst_ports'] = float(len(set(dst_ports)))
        features['port_entropy'] = self._calculate_entropy([str(p) for p in dst_ports])
        
        # Bytes per packet analysis
        bytes_per_packet = [f.bytes_per_packet_sent() for f in window_flows if f.packets_sent > 0]
        if bytes_per_packet:
            features['avg_bytes_per_packet'] = float(statistics.mean(bytes_per_packet))
            features['bytes_per_packet_std'] = float(statistics.stdev(bytes_per_packet) if len(bytes_per_packet) > 1 else 0.0)
        else:
            features['avg_bytes_per_packet'] = 0.0
            features['bytes_per_packet_std'] = 0.0
        
        # Create feature vector
        feature_names = sorted(features.keys())
        device_id = f"{window_flows[0].source_ip}"  # Simplified device identification
        
        feature_vector = FeatureVector(
            flow_id=f"temporal_{window.start_time.isoformat()}",
            timestamp=window.start_time,
            device_id=device_id,
            features=features,
            feature_names=feature_names,
            window=window
        )
        
        self.features_extracted += 1
        return feature_vector
    
    async def extract_device_features(self, device_id: str, 
                                    flows: List[NetworkFlow]) -> Dict[str, float]:
        """
        Extract device-specific behavioral features.
        
        Args:
            device_id: Device identifier (MAC address or IP)
            flows: Historical flows for the device
            
        Returns:
            Dictionary of device behavioral features
        """
        if not flows:
            return {}
        
        features = {}
        
        # Communication patterns
        destinations = set(f.destination_ip for f in flows)
        sources = set(f.source_ip for f in flows)
        
        features['unique_destinations'] = float(len(destinations))
        features['unique_sources'] = float(len(sources))
        features['communication_diversity'] = float(len(destinations) + len(sources))
        
        # Temporal patterns
        timestamps = [f.timestamp for f in flows]
        if len(timestamps) > 1:
            time_deltas = []
            for i in range(1, len(timestamps)):
                delta = (timestamps[i] - timestamps[i-1]).total_seconds()
                time_deltas.append(delta)
            
            features['avg_inter_flow_time'] = float(statistics.mean(time_deltas))
            features['inter_flow_time_std'] = float(statistics.stdev(time_deltas) if len(time_deltas) > 1 else 0.0)
        else:
            features['avg_inter_flow_time'] = 0.0
            features['inter_flow_time_std'] = 0.0
        
        # Protocol preferences
        protocols = [f.protocol for f in flows]
        protocol_counts = Counter(protocols)
        total_flows = len(flows)
        
        for protocol in ['TCP', 'UDP', 'ICMP']:
            features[f'{protocol.lower()}_preference'] = float(protocol_counts.get(protocol, 0) / total_flows)
        
        # Bandwidth characteristics
        total_bytes = sum(f.total_bytes() for f in flows)
        total_duration = sum(f.duration_ms for f in flows if f.duration_ms > 0)
        
        features['total_bandwidth_bytes'] = float(total_bytes)
        features['avg_bandwidth_bps'] = float(total_bytes * 8 / (total_duration / 1000)) if total_duration > 0 else 0.0
        
        return features
    
    async def extract_dns_features(self, metadata: ProtocolMetadata) -> Dict[str, float]:
        """
        Extract DNS-specific features for threat detection.
        
        Args:
            metadata: Protocol metadata containing DNS information
            
        Returns:
            Dictionary of DNS-specific features
        """
        features = {}
        
        if not self.enable_dns_features or metadata.protocol != ProtocolType.DNS:
            return features
        
        if metadata.dns_query:
            query = metadata.dns_query
            
            # Query length and structure
            features['dns_query_length'] = float(len(query))
            features['dns_subdomain_count'] = float(len(query.split('.')) - 1)
            
            # Domain entropy (indicator of DGA domains)
            features['dns_query_entropy'] = self._calculate_entropy(query)
            
            # Character analysis
            features['dns_digit_ratio'] = float(sum(c.isdigit() for c in query) / len(query))
            features['dns_vowel_ratio'] = float(sum(c.lower() in 'aeiou' for c in query) / len(query))
            
            # Suspicious patterns
            features['dns_has_numbers'] = float(any(c.isdigit() for c in query))
            features['dns_has_hyphens'] = float('-' in query)
            features['dns_length_suspicious'] = float(len(query) > 50 or len(query) < 3)
        
        # Response analysis
        if metadata.dns_response_code:
            features['dns_nxdomain'] = float(metadata.dns_response_code == 'NXDOMAIN')
            features['dns_response_success'] = float(metadata.dns_response_code == 'NOERROR')
        
        if metadata.dns_answers:
            features['dns_answer_count'] = float(len(metadata.dns_answers))
            # Check for suspicious IP patterns in answers
            suspicious_ips = 0
            for answer in metadata.dns_answers:
                if self._is_suspicious_ip(answer):
                    suspicious_ips += 1
            features['dns_suspicious_ip_ratio'] = float(suspicious_ips / len(metadata.dns_answers))
        else:
            features['dns_answer_count'] = 0.0
            features['dns_suspicious_ip_ratio'] = 0.0
        
        return features
    
    async def extract_tls_features(self, metadata: ProtocolMetadata) -> Dict[str, float]:
        """
        Extract TLS-specific features for threat detection.
        
        Args:
            metadata: Protocol metadata containing TLS information
            
        Returns:
            Dictionary of TLS-specific features
        """
        features = {}
        
        if not self.enable_tls_features or metadata.protocol != ProtocolType.TLS:
            return features
        
        # SNI analysis
        if metadata.tls_sni:
            sni = metadata.tls_sni
            features['tls_sni_length'] = float(len(sni))
            features['tls_sni_entropy'] = self._calculate_entropy(sni)
            features['tls_sni_subdomain_count'] = float(len(sni.split('.')) - 1)
            
            # Check for suspicious SNI patterns
            features['tls_sni_has_ip'] = float(self._looks_like_ip(sni))
            features['tls_sni_suspicious_tld'] = float(self._has_suspicious_tld(sni))
        else:
            features['tls_sni_present'] = 0.0
        
        # JA3 fingerprinting
        if metadata.tls_ja3_fingerprint:
            features['tls_ja3_present'] = 1.0
            features['tls_ja3_hash'] = float(hash(metadata.tls_ja3_fingerprint) % 1000000)  # Simplified hash
        else:
            features['tls_ja3_present'] = 0.0
            features['tls_ja3_hash'] = 0.0
        
        if metadata.tls_ja3s_fingerprint:
            features['tls_ja3s_present'] = 1.0
            features['tls_ja3s_hash'] = float(hash(metadata.tls_ja3s_fingerprint) % 1000000)
        else:
            features['tls_ja3s_present'] = 0.0
            features['tls_ja3s_hash'] = 0.0
        
        # TLS version analysis
        if metadata.tls_version:
            version_scores = {
                'TLSv1.3': 1.0,
                'TLSv1.2': 0.8,
                'TLSv1.1': 0.4,
                'TLSv1.0': 0.2,
                'SSLv3': 0.0,
                'SSLv2': 0.0
            }
            features['tls_version_score'] = version_scores.get(metadata.tls_version, 0.5)
        else:
            features['tls_version_score'] = 0.0
        
        return features
    
    async def calculate_directional_metrics(self, flows: List[NetworkFlow]) -> Dict[str, float]:
        """
        Calculate directional communication metrics.
        
        Args:
            flows: List of network flows for analysis
            
        Returns:
            Dictionary containing directional metrics
        """
        if not flows:
            return {}
        
        # Group flows by source IP (device)
        device_flows = defaultdict(list)
        for flow in flows:
            device_flows[flow.source_ip].append(flow)
        
        metrics = {}
        
        # Calculate fan-out and fan-in ratios
        total_fan_out = 0
        total_fan_in = 0
        device_count = len(device_flows)
        
        for device_ip, device_flow_list in device_flows.items():
            # Fan-out: unique destinations per device
            destinations = set(f.destination_ip for f in device_flow_list)
            fan_out = len(destinations)
            total_fan_out += fan_out
            
            # Fan-in: count flows where this device is destination
            fan_in = sum(1 for f in flows if f.destination_ip == device_ip)
            total_fan_in += fan_in
        
        metrics['avg_fan_out'] = float(total_fan_out / device_count) if device_count > 0 else 0.0
        metrics['avg_fan_in'] = float(total_fan_in / device_count) if device_count > 0 else 0.0
        metrics['fan_out_ratio'] = float(total_fan_out / len(flows)) if flows else 0.0
        metrics['fan_in_ratio'] = float(total_fan_in / len(flows)) if flows else 0.0
        
        # Port distribution analysis
        src_ports = [f.source_port for f in flows]
        dst_ports = [f.destination_port for f in flows]
        
        metrics['src_port_entropy'] = self._calculate_entropy([str(p) for p in src_ports])
        metrics['dst_port_entropy'] = self._calculate_entropy([str(p) for p in dst_ports])
        metrics['port_distribution_entropy'] = (metrics['src_port_entropy'] + metrics['dst_port_entropy']) / 2
        
        # Protocol diversity
        protocols = [f.protocol for f in flows]
        metrics['protocol_diversity'] = float(len(set(protocols)))
        metrics['protocol_entropy'] = self._calculate_entropy(protocols)
        
        return metrics
    
    async def calculate_timing_features(self, flows: List[NetworkFlow]) -> Dict[str, float]:
        """
        Calculate timing-based features from flow data.
        
        Args:
            flows: List of network flows for timing analysis
            
        Returns:
            Dictionary containing timing features
        """
        if not flows:
            return {}
        
        # Sort flows by timestamp
        sorted_flows = sorted(flows, key=lambda f: f.timestamp)
        
        features = {}
        
        # Inter-arrival time analysis
        if len(sorted_flows) > 1:
            inter_arrivals = []
            for i in range(1, len(sorted_flows)):
                delta = (sorted_flows[i].timestamp - sorted_flows[i-1].timestamp).total_seconds()
                inter_arrivals.append(delta)
            
            features['inter_arrival_mean'] = float(statistics.mean(inter_arrivals))
            features['inter_arrival_std'] = float(statistics.stdev(inter_arrivals) if len(inter_arrivals) > 1 else 0.0)
            features['inter_arrival_min'] = float(min(inter_arrivals))
            features['inter_arrival_max'] = float(max(inter_arrivals))
        else:
            features['inter_arrival_mean'] = 0.0
            features['inter_arrival_std'] = 0.0
            features['inter_arrival_min'] = 0.0
            features['inter_arrival_max'] = 0.0
        
        # Periodicity analysis (simplified)
        if len(sorted_flows) > 3:
            # Look for periodic patterns in inter-arrival times
            inter_arrivals = [(sorted_flows[i].timestamp - sorted_flows[i-1].timestamp).total_seconds() 
                            for i in range(1, len(sorted_flows))]
            
            # Simple periodicity score based on coefficient of variation
            if statistics.mean(inter_arrivals) > 0:
                cv = statistics.stdev(inter_arrivals) / statistics.mean(inter_arrivals)
                features['periodicity_score'] = float(1.0 / (1.0 + cv))  # Lower CV = higher periodicity
            else:
                features['periodicity_score'] = 0.0
        else:
            features['periodicity_score'] = 0.0
        
        # Burst detection
        durations = [f.duration_ms for f in flows if f.duration_ms > 0]
        if durations:
            short_flows = sum(1 for d in durations if d < 1000)  # < 1 second
            features['burst_ratio'] = float(short_flows / len(durations))
        else:
            features['burst_ratio'] = 0.0
        
        # Time-of-day patterns (hour of day)
        hours = [f.timestamp.hour for f in flows]
        hour_counts = Counter(hours)
        features['time_diversity'] = float(len(hour_counts))
        features['peak_hour_ratio'] = float(max(hour_counts.values()) / len(flows)) if flows else 0.0
        
        return features
    
    async def normalize_features(self, feature_vector: FeatureVector) -> FeatureVector:
        """
        Normalize feature values for ML model consumption.
        
        Args:
            feature_vector: Raw feature vector to normalize
            
        Returns:
            Normalized feature vector with values scaled appropriately
        """
        normalized_features = {}
        
        for feature_name, value in feature_vector.features.items():
            # Apply different normalization strategies based on feature type
            if 'ratio' in feature_name or 'entropy' in feature_name:
                # Already normalized features (0-1 range)
                normalized_features[feature_name] = max(0.0, min(1.0, value))
            elif 'count' in feature_name or 'diversity' in feature_name:
                # Log normalization for count features
                normalized_features[feature_name] = math.log1p(value) / 10.0
            elif 'bytes' in feature_name or 'bandwidth' in feature_name:
                # Log normalization for size features
                normalized_features[feature_name] = math.log1p(value) / 20.0
            elif 'time' in feature_name or 'duration' in feature_name:
                # Time features - normalize to reasonable ranges
                normalized_features[feature_name] = min(1.0, value / 3600.0)  # Normalize to hours
            else:
                # Default: min-max normalization assuming reasonable ranges
                normalized_features[feature_name] = max(0.0, min(1.0, value / 100.0))
        
        return FeatureVector(
            flow_id=feature_vector.flow_id,
            timestamp=feature_vector.timestamp,
            device_id=feature_vector.device_id,
            features=normalized_features,
            feature_names=feature_vector.feature_names,
            window=feature_vector.window
        )
    
    async def get_feature_importance(self) -> Dict[str, float]:
        """
        Get feature importance scores for explainability.
        
        Returns:
            Dictionary mapping feature names to importance scores
        """
        return self.feature_importance.copy()
    
    async def create_time_windows(self, start_time: datetime, 
                                end_time: datetime, 
                                window_size_minutes: int) -> List[FlowWindow]:
        """
        Create time windows for temporal feature extraction.
        
        Args:
            start_time: Start of time range
            end_time: End of time range
            window_size_minutes: Size of each window in minutes
            
        Returns:
            List of non-overlapping time windows
        """
        windows = []
        current_time = start_time
        window_delta = timedelta(minutes=window_size_minutes)
        
        while current_time < end_time:
            window_end = min(current_time + window_delta, end_time)
            window = FlowWindow(
                start_time=current_time,
                end_time=window_end,
                duration_seconds=int((window_end - current_time).total_seconds())
            )
            windows.append(window)
            current_time = window_end
        
        return windows
    
    async def get_extraction_statistics(self) -> Dict[str, Any]:
        """
        Get feature extraction statistics and performance metrics.
        
        Returns:
            Dictionary containing extraction statistics
        """
        current_time = datetime.utcnow()
        uptime_seconds = (current_time - self.processing_start_time).total_seconds() if self.processing_start_time else 0
        
        return {
            "flows_processed": self.flows_processed,
            "features_extracted": self.features_extracted,
            "extraction_rate_fps": self.flows_processed / uptime_seconds if uptime_seconds > 0 else 0.0,
            "feature_dimensions": len(self.feature_importance),
            "processing_latency_ms": 0.0,  # Would need actual timing measurements
            "uptime_seconds": uptime_seconds,
            "dns_features_enabled": self.enable_dns_features,
            "tls_features_enabled": self.enable_tls_features
        }
    
    def _group_metadata_by_flow(self, metadata_list: List[ProtocolMetadata]) -> Dict[tuple, List[ProtocolMetadata]]:
        """Group protocol metadata by flow 5-tuple."""
        flow_groups = defaultdict(list)
        
        for metadata in metadata_list:
            protocol_val = metadata.protocol.value if hasattr(metadata.protocol, 'value') else metadata.protocol
            flow_key = (
                metadata.source_ip,
                metadata.destination_ip,
                metadata.source_port,
                metadata.destination_port,
                protocol_val
            )
            flow_groups[flow_key].append(metadata)
        
        return dict(flow_groups)
    
    def _calculate_entropy(self, values: List[str]) -> float:
        """Calculate Shannon entropy of a list of values."""
        if not values:
            return 0.0
        
        counts = Counter(values)
        total = len(values)
        entropy = 0.0
        
        for count in counts.values():
            probability = count / total
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _is_suspicious_ip(self, ip_str: str) -> bool:
        """Check if an IP address looks suspicious."""
        # Simple heuristics for suspicious IPs
        try:
            parts = ip_str.split('.')
            if len(parts) == 4:
                # Check for private/reserved ranges that might be suspicious in DNS responses
                first_octet = int(parts[0])
                if first_octet in [0, 127, 169, 224, 240]:  # Reserved ranges
                    return True
        except (ValueError, IndexError):
            pass
        return False
    
    def _looks_like_ip(self, domain: str) -> bool:
        """Check if a domain name looks like an IP address."""
        try:
            parts = domain.split('.')
            if len(parts) == 4:
                for part in parts:
                    int(part)  # Will raise ValueError if not numeric
                return True
        except ValueError:
            pass
        return False
    
    def _has_suspicious_tld(self, domain: str) -> bool:
        """Check if domain has a suspicious top-level domain."""
        suspicious_tlds = {'.tk', '.ml', '.ga', '.cf', '.bit', '.onion'}
        return any(domain.endswith(tld) for tld in suspicious_tlds)