#!/usr/bin/env python3
"""
Feature Extractor Demo for AI-driven IoT IDS

This script demonstrates the NetworkFlowExtractor functionality including:
- Flow-level feature extraction from protocol metadata
- DNS and TLS-specific feature extraction
- Directional metrics calculation
- Temporal feature analysis
"""

import asyncio
from datetime import datetime, timedelta
from typing import List

from ai_iot_ids.extractors.network_flow_extractor import NetworkFlowExtractor
from ai_iot_ids.interfaces.feature_extractor import FlowWindow
from ai_iot_ids.interfaces.protocol_decoder import ProtocolMetadata, ProtocolType
from ai_iot_ids.models.network_flow import NetworkFlow


async def demo_basic_flow_extraction():
    """Demonstrate basic flow feature extraction from TCP metadata."""
    print("=== Basic Flow Feature Extraction Demo ===")
    
    # Configure the feature extractor
    config = {
        'time_window_minutes': 5,
        'enable_dns_features': True,
        'enable_tls_features': True
    }
    
    extractor = NetworkFlowExtractor(config)
    await extractor.initialize()
    await extractor.start()
    
    # Create sample TCP metadata
    base_time = datetime.utcnow()
    tcp_metadata = []
    
    for i in range(3):
        metadata = ProtocolMetadata(
            protocol=ProtocolType.TCP,
            timestamp=base_time + timedelta(milliseconds=i*100),
            source_ip="192.168.1.100",
            destination_ip="8.8.8.8",
            source_port=45123,
            destination_port=80,
            tcp_flags=["SYN", "ACK"] if i == 0 else ["ACK"],
            tcp_sequence_number=1000 + i,
            payload_size=1024 + i*100
        )
        tcp_metadata.append(metadata)
    
    # Extract flow features
    flow = await extractor.extract_flow_features(tcp_metadata)
    
    print(f"Extracted Flow:")
    print(f"  Source: {flow.source_ip}:{flow.source_port}")
    print(f"  Destination: {flow.destination_ip}:{flow.destination_port}")
    print(f"  Protocol: {flow.protocol}")
    print(f"  Total bytes: {flow.bytes_sent}")
    print(f"  Total packets: {flow.packets_sent}")
    print(f"  Duration: {flow.duration_ms}ms")
    print(f"  Inter-arrival mean: {flow.inter_arrival_mean_ms:.2f}ms")
    print(f"  TCP flags: {flow.tcp_flags}")
    print()
    
    await extractor.stop()


async def demo_dns_feature_extraction():
    """Demonstrate DNS-specific feature extraction."""
    print("=== DNS Feature Extraction Demo ===")
    
    config = {'enable_dns_features': True}
    extractor = NetworkFlowExtractor(config)
    await extractor.initialize()
    await extractor.start()
    
    # Create DNS metadata samples
    dns_samples = [
        {
            'query': 'example.com',
            'response_code': 'NOERROR',
            'answers': ['93.184.216.34']
        },
        {
            'query': 'suspicious-long-domain-name-that-might-be-dga.malware.com',
            'response_code': 'NXDOMAIN',
            'answers': []
        },
        {
            'query': 'test123456.example.org',
            'response_code': 'NOERROR',
            'answers': ['192.168.1.1', '10.0.0.1']
        }
    ]
    
    for i, sample in enumerate(dns_samples):
        metadata = ProtocolMetadata(
            protocol=ProtocolType.DNS,
            timestamp=datetime.utcnow(),
            source_ip="192.168.1.100",
            destination_ip="8.8.8.8",
            source_port=45123 + i,
            destination_port=53,
            dns_query=sample['query'],
            dns_query_type="A",
            dns_response_code=sample['response_code'],
            dns_answers=sample['answers'],
            payload_size=len(sample['query']) + 20
        )
        
        features = await extractor.extract_dns_features(metadata)
        
        print(f"DNS Query: {sample['query']}")
        print(f"  Query length: {features.get('dns_query_length', 0)}")
        print(f"  Subdomain count: {features.get('dns_subdomain_count', 0)}")
        print(f"  Query entropy: {features.get('dns_query_entropy', 0):.3f}")
        print(f"  Digit ratio: {features.get('dns_digit_ratio', 0):.3f}")
        print(f"  Answer count: {features.get('dns_answer_count', 0)}")
        print(f"  NXDOMAIN: {features.get('dns_nxdomain', 0)}")
        print()
    
    await extractor.stop()


async def demo_tls_feature_extraction():
    """Demonstrate TLS-specific feature extraction."""
    print("=== TLS Feature Extraction Demo ===")
    
    config = {'enable_tls_features': True}
    extractor = NetworkFlowExtractor(config)
    await extractor.initialize()
    await extractor.start()
    
    # Create TLS metadata samples
    tls_samples = [
        {
            'sni': 'www.google.com',
            'version': 'TLSv1.3',
            'ja3': '769,47-53-5-10-49161-49162',
            'ja3s': '769,47,65281'
        },
        {
            'sni': 'suspicious.malware.tk',
            'version': 'TLSv1.0',
            'ja3': '769,4-5-10-9-100-18-3-6',
            'ja3s': None
        },
        {
            'sni': '192.168.1.1',  # IP address as SNI (suspicious)
            'version': 'TLSv1.2',
            'ja3': None,
            'ja3s': None
        }
    ]
    
    for i, sample in enumerate(tls_samples):
        metadata = ProtocolMetadata(
            protocol=ProtocolType.TLS,
            timestamp=datetime.utcnow(),
            source_ip="192.168.1.100",
            destination_ip="93.184.216.34",
            source_port=45123 + i,
            destination_port=443,
            tls_sni=sample['sni'],
            tls_version=sample['version'],
            tls_ja3_fingerprint=sample['ja3'],
            tls_ja3s_fingerprint=sample['ja3s'],
            payload_size=512
        )
        
        features = await extractor.extract_tls_features(metadata)
        
        print(f"TLS Connection: {sample['sni']}")
        print(f"  SNI length: {features.get('tls_sni_length', 0)}")
        print(f"  SNI entropy: {features.get('tls_sni_entropy', 0):.3f}")
        print(f"  SNI has IP: {features.get('tls_sni_has_ip', 0)}")
        print(f"  Suspicious TLD: {features.get('tls_sni_suspicious_tld', 0)}")
        print(f"  JA3 present: {features.get('tls_ja3_present', 0)}")
        print(f"  JA3S present: {features.get('tls_ja3s_present', 0)}")
        print(f"  Version score: {features.get('tls_version_score', 0):.1f}")
        print()
    
    await extractor.stop()


async def demo_directional_metrics():
    """Demonstrate directional metrics calculation."""
    print("=== Directional Metrics Demo ===")
    
    config = {}
    extractor = NetworkFlowExtractor(config)
    await extractor.initialize()
    await extractor.start()
    
    # Create flows showing different communication patterns
    flows = []
    base_time = datetime.utcnow()
    
    # Device 1: High fan-out (talks to many destinations)
    destinations = ["8.8.8.8", "1.1.1.1", "208.67.222.222", "9.9.9.9"]
    for i, dst in enumerate(destinations):
        flow = NetworkFlow(
            timestamp=base_time + timedelta(seconds=i),
            source_ip="192.168.1.100",
            destination_ip=dst,
            source_port=45123 + i,
            destination_port=53,
            protocol="UDP",
            bytes_sent=64,
            bytes_received=128,
            packets_sent=1,
            packets_received=1,
            duration_ms=100,
            inter_arrival_mean_ms=0.0,
            inter_arrival_std_ms=0.0,
            jitter_ms=0.0
        )
        flows.append(flow)
    
    # Device 2: Normal communication pattern
    for i in range(2):
        flow = NetworkFlow(
            timestamp=base_time + timedelta(seconds=10 + i),
            source_ip="192.168.1.101",
            destination_ip="8.8.8.8",
            source_port=45200 + i,
            destination_port=80,
            protocol="TCP",
            bytes_sent=1024,
            bytes_received=2048,
            packets_sent=3,
            packets_received=2,
            duration_ms=1000,
            inter_arrival_mean_ms=0.0,
            inter_arrival_std_ms=0.0,
            jitter_ms=0.0
        )
        flows.append(flow)
    
    # Calculate directional metrics
    metrics = await extractor.calculate_directional_metrics(flows)
    
    print("Communication Pattern Analysis:")
    print(f"  Average fan-out: {metrics['avg_fan_out']:.2f}")
    print(f"  Average fan-in: {metrics['avg_fan_in']:.2f}")
    print(f"  Fan-out ratio: {metrics['fan_out_ratio']:.3f}")
    print(f"  Fan-in ratio: {metrics['fan_in_ratio']:.3f}")
    print(f"  Destination port entropy: {metrics['dst_port_entropy']:.3f}")
    print(f"  Protocol diversity: {metrics['protocol_diversity']}")
    print(f"  Protocol entropy: {metrics['protocol_entropy']:.3f}")
    print()
    
    await extractor.stop()


async def demo_timing_analysis():
    """Demonstrate timing feature analysis."""
    print("=== Timing Analysis Demo ===")
    
    config = {}
    extractor = NetworkFlowExtractor(config)
    await extractor.initialize()
    await extractor.start()
    
    # Create flows with different timing patterns
    base_time = datetime.utcnow()
    
    # Regular periodic pattern (every 30 seconds)
    periodic_flows = []
    for i in range(5):
        flow = NetworkFlow(
            timestamp=base_time + timedelta(seconds=i*30),
            source_ip="192.168.1.100",
            destination_ip="93.184.216.34",  # IP for api.example.com
            source_port=45123,
            destination_port=443,
            protocol="TCP",
            bytes_sent=256,
            bytes_received=512,
            packets_sent=2,
            packets_received=3,
            duration_ms=500,
            inter_arrival_mean_ms=0.0,
            inter_arrival_std_ms=0.0,
            jitter_ms=0.0
        )
        periodic_flows.append(flow)
    
    # Bursty pattern (quick succession then gap)
    bursty_flows = []
    for i in range(3):
        flow = NetworkFlow(
            timestamp=base_time + timedelta(milliseconds=i*100),
            source_ip="192.168.1.101",
            destination_ip="151.101.193.140",  # IP for cdn.example.com
            source_port=45200 + i,
            destination_port=80,
            protocol="TCP",
            bytes_sent=1024,
            bytes_received=4096,
            packets_sent=1,
            packets_received=3,
            duration_ms=50,  # Short duration = bursty
            inter_arrival_mean_ms=0.0,
            inter_arrival_std_ms=0.0,
            jitter_ms=0.0
        )
        bursty_flows.append(flow)
    
    # Analyze periodic pattern
    periodic_features = await extractor.calculate_timing_features(periodic_flows)
    print("Periodic Pattern Analysis:")
    print(f"  Inter-arrival mean: {periodic_features['inter_arrival_mean']:.1f}s")
    print(f"  Inter-arrival std: {periodic_features['inter_arrival_std']:.3f}s")
    print(f"  Periodicity score: {periodic_features['periodicity_score']:.3f}")
    print(f"  Burst ratio: {periodic_features['burst_ratio']:.3f}")
    print()
    
    # Analyze bursty pattern
    bursty_features = await extractor.calculate_timing_features(bursty_flows)
    print("Bursty Pattern Analysis:")
    print(f"  Inter-arrival mean: {bursty_features['inter_arrival_mean']:.3f}s")
    print(f"  Inter-arrival std: {bursty_features['inter_arrival_std']:.3f}s")
    print(f"  Periodicity score: {bursty_features['periodicity_score']:.3f}")
    print(f"  Burst ratio: {bursty_features['burst_ratio']:.3f}")
    print()
    
    await extractor.stop()


async def demo_feature_importance():
    """Demonstrate feature importance and statistics."""
    print("=== Feature Importance and Statistics Demo ===")
    
    config = {
        'enable_dns_features': True,
        'enable_tls_features': True
    }
    extractor = NetworkFlowExtractor(config)
    await extractor.initialize()
    await extractor.start()
    
    # Get feature importance scores
    importance = await extractor.get_feature_importance()
    print("Feature Importance Scores:")
    for feature, score in sorted(importance.items(), key=lambda x: x[1], reverse=True):
        print(f"  {feature}: {score:.3f}")
    print()
    
    # Process some sample data to generate statistics
    metadata = ProtocolMetadata(
        protocol=ProtocolType.TCP,
        timestamp=datetime.utcnow(),
        source_ip="192.168.1.100",
        destination_ip="8.8.8.8",
        source_port=45123,
        destination_port=80,
        payload_size=1024
    )
    
    await extractor.extract_flow_features([metadata])
    
    # Get extraction statistics
    stats = await extractor.get_extraction_statistics()
    print("Extraction Statistics:")
    print(f"  Flows processed: {stats['flows_processed']}")
    print(f"  Features extracted: {stats['features_extracted']}")
    print(f"  Feature dimensions: {stats['feature_dimensions']}")
    print(f"  DNS features enabled: {stats['dns_features_enabled']}")
    print(f"  TLS features enabled: {stats['tls_features_enabled']}")
    print(f"  Uptime: {stats['uptime_seconds']:.1f}s")
    print()
    
    # Health check
    health = await extractor.health_check()
    print("Health Status:")
    print(f"  Status: {health['status']}")
    print(f"  Initialized: {health['initialized']}")
    print(f"  Running: {health['running']}")
    print(f"  Feature count: {health['feature_count']}")
    print()
    
    await extractor.stop()


async def main():
    """Run all feature extractor demos."""
    print("AI-driven IoT IDS - Feature Extractor Demo")
    print("=" * 50)
    print()
    
    try:
        await demo_basic_flow_extraction()
        await demo_dns_feature_extraction()
        await demo_tls_feature_extraction()
        await demo_directional_metrics()
        await demo_timing_analysis()
        await demo_feature_importance()
        
        print("Demo completed successfully!")
        
    except Exception as e:
        print(f"Demo failed with error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())