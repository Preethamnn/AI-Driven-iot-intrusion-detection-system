#!/usr/bin/env python3
"""
Protocol Decoder Integration Demo

This script demonstrates how to use the Zeek, Suricata, and Hybrid protocol decoders
to analyze network packets and extract protocol metadata.
"""

import asyncio
import tempfile
from datetime import datetime
from pathlib import Path

from ai_iot_ids.decoders.zeek_decoder import ZeekDecoder
from ai_iot_ids.decoders.suricata_decoder import SuricataDecoder
from ai_iot_ids.decoders.hybrid_decoder import HybridDecoder
from ai_iot_ids.interfaces.packet_capture import RawPacket


async def create_sample_packets():
    """Create sample network packets for demonstration."""
    # These are simplified packet examples - in real usage, you'd get these from packet capture
    packets = [
        RawPacket(
            timestamp=datetime.now(),
            data=b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x08\x00' + b'\x45\x00' + b'\x00' * 50,
            interface="eth0",
            length=64
        ),
        RawPacket(
            timestamp=datetime.now(),
            data=b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x08\x06' + b'\x45\x00' + b'\x00' * 50,
            interface="eth0",
            length=64
        )
    ]
    return packets


async def demo_zeek_decoder():
    """Demonstrate Zeek decoder functionality."""
    print("=== Zeek Decoder Demo ===")
    
    with tempfile.TemporaryDirectory() as temp_dir:
        # Create a mock Zeek binary for demo
        zeek_binary = Path(temp_dir) / "zeek"
        zeek_binary.write_text("#!/bin/bash\necho 'zeek version 4.0.0'\nexit 0\n")
        zeek_binary.chmod(0o755)
        
        # Initialize decoder
        decoder = ZeekDecoder(
            zeek_binary_path=str(zeek_binary),
            temp_dir=temp_dir
        )
        
        try:
            # This would normally work with a real Zeek installation
            print(f"Zeek decoder created with binary: {zeek_binary}")
            print(f"Supported protocols: {await decoder.get_supported_protocols()}")
            print(f"Statistics: {await decoder.get_decoder_statistics()}")
            
        except Exception as e:
            print(f"Demo limitation (expected): {e}")


async def demo_suricata_decoder():
    """Demonstrate Suricata decoder functionality."""
    print("\n=== Suricata Decoder Demo ===")
    
    with tempfile.TemporaryDirectory() as temp_dir:
        # Create a mock Suricata binary for demo
        suricata_binary = Path(temp_dir) / "suricata"
        suricata_binary.write_text("#!/bin/bash\necho 'Suricata 6.0.0'\nexit 0\n")
        suricata_binary.chmod(0o755)
        
        # Initialize decoder
        decoder = SuricataDecoder(
            suricata_binary_path=str(suricata_binary),
            temp_dir=temp_dir
        )
        
        try:
            # This would normally work with a real Suricata installation
            print(f"Suricata decoder created with binary: {suricata_binary}")
            print(f"Supported protocols: {await decoder.get_supported_protocols()}")
            print(f"Statistics: {await decoder.get_decoder_statistics()}")
            
        except Exception as e:
            print(f"Demo limitation (expected): {e}")


async def demo_hybrid_decoder():
    """Demonstrate Hybrid decoder functionality."""
    print("\n=== Hybrid Decoder Demo ===")
    
    with tempfile.TemporaryDirectory() as temp_dir:
        # Create mock binaries
        zeek_binary = Path(temp_dir) / "zeek"
        zeek_binary.write_text("#!/bin/bash\necho 'zeek version 4.0.0'\nexit 0\n")
        zeek_binary.chmod(0o755)
        
        suricata_binary = Path(temp_dir) / "suricata"
        suricata_binary.write_text("#!/bin/bash\necho 'Suricata 6.0.0'\nexit 0\n")
        suricata_binary.chmod(0o755)
        
        # Initialize hybrid decoder
        decoder = HybridDecoder(
            zeek_config={
                "zeek_binary_path": str(zeek_binary),
                "temp_dir": temp_dir
            },
            suricata_config={
                "suricata_binary_path": str(suricata_binary),
                "temp_dir": temp_dir
            },
            mode="both"
        )
        
        print(f"Hybrid decoder created in 'both' mode")
        print(f"Mode: {decoder.mode}")
        print(f"Primary decoder: {decoder.primary_decoder}")
        print(f"Merge metadata: {decoder.merge_metadata}")
        
        # Show different modes
        modes = ["both", "zeek", "suricata", "fallback"]
        for mode in modes:
            try:
                test_decoder = HybridDecoder(mode=mode)
                print(f"✓ Mode '{mode}' supported")
            except Exception as e:
                print(f"✗ Mode '{mode}' error: {e}")


async def demo_protocol_metadata():
    """Demonstrate protocol metadata extraction."""
    print("\n=== Protocol Metadata Demo ===")
    
    # Show the types of metadata that can be extracted
    from ai_iot_ids.interfaces.protocol_decoder import ProtocolMetadata, ProtocolType
    
    # Example HTTP metadata
    http_metadata = ProtocolMetadata(
        protocol=ProtocolType.HTTP,
        timestamp=datetime.now(),
        source_ip="192.168.1.100",
        destination_ip="192.168.1.1",
        source_port=12345,
        destination_port=80,
        http_method="GET",
        http_uri="/api/data",
        http_user_agent="IoT-Device/1.0",
        http_status_code=200,
        payload_size=1024
    )
    
    print("Example HTTP metadata:")
    print(f"  Protocol: {http_metadata.protocol}")
    print(f"  Source: {http_metadata.source_ip}:{http_metadata.source_port}")
    print(f"  Destination: {http_metadata.destination_ip}:{http_metadata.destination_port}")
    print(f"  HTTP Method: {http_metadata.http_method}")
    print(f"  HTTP URI: {http_metadata.http_uri}")
    print(f"  HTTP Status: {http_metadata.http_status_code}")
    print(f"  Payload Size: {http_metadata.payload_size} bytes")
    
    # Example DNS metadata
    dns_metadata = ProtocolMetadata(
        protocol=ProtocolType.DNS,
        timestamp=datetime.now(),
        source_ip="192.168.1.100",
        destination_ip="8.8.8.8",
        source_port=54321,
        destination_port=53,
        dns_query="example.com",
        dns_query_type="A",
        dns_response_code="NOERROR",
        dns_answers=["93.184.216.34"]
    )
    
    print("\nExample DNS metadata:")
    print(f"  Protocol: {dns_metadata.protocol}")
    print(f"  Query: {dns_metadata.dns_query}")
    print(f"  Query Type: {dns_metadata.dns_query_type}")
    print(f"  Response Code: {dns_metadata.dns_response_code}")
    print(f"  Answers: {dns_metadata.dns_answers}")
    
    # Example TLS metadata
    tls_metadata = ProtocolMetadata(
        protocol=ProtocolType.TLS,
        timestamp=datetime.now(),
        source_ip="192.168.1.100",
        destination_ip="93.184.216.34",
        source_port=12345,
        destination_port=443,
        tls_version="TLS 1.3",
        tls_sni="example.com",
        tls_ja3_fingerprint="abc123def456",
        tls_ja3s_fingerprint="789xyz012"
    )
    
    print("\nExample TLS metadata:")
    print(f"  Protocol: {tls_metadata.protocol}")
    print(f"  TLS Version: {tls_metadata.tls_version}")
    print(f"  SNI: {tls_metadata.tls_sni}")
    print(f"  JA3 Fingerprint: {tls_metadata.tls_ja3_fingerprint}")
    print(f"  JA3S Fingerprint: {tls_metadata.tls_ja3s_fingerprint}")


async def demo_signature_alerts():
    """Demonstrate signature alert functionality."""
    print("\n=== Signature Alert Demo ===")
    
    from ai_iot_ids.interfaces.protocol_decoder import SignatureAlert
    
    # Example signature alert
    alert = SignatureAlert(
        rule_id="1:2001",
        rule_name="ET SCAN Potential SSH Scan",
        severity="high",
        category="Attempted Information Leak",
        timestamp=datetime.now(),
        source_ip="192.168.1.100",
        destination_ip="192.168.1.1",
        source_port=12345,
        destination_port=22,
        protocol="TCP",
        message="Multiple SSH connection attempts detected"
    )
    
    print("Example signature alert:")
    print(f"  Rule ID: {alert.rule_id}")
    print(f"  Rule Name: {alert.rule_name}")
    print(f"  Severity: {alert.severity}")
    print(f"  Category: {alert.category}")
    print(f"  Source: {alert.source_ip}:{alert.source_port}")
    print(f"  Destination: {alert.destination_ip}:{alert.destination_port}")
    print(f"  Protocol: {alert.protocol}")
    print(f"  Message: {alert.message}")


async def main():
    """Run all protocol decoder demonstrations."""
    print("Protocol Decoder Integration Demo")
    print("=" * 50)
    
    await demo_zeek_decoder()
    await demo_suricata_decoder()
    await demo_hybrid_decoder()
    await demo_protocol_metadata()
    await demo_signature_alerts()
    
    print("\n" + "=" * 50)
    print("Demo completed!")
    print("\nNote: This demo uses mock binaries for demonstration.")
    print("In production, you would need actual Zeek and Suricata installations.")
    print("\nKey Features Demonstrated:")
    print("- Zeek integration for protocol analysis")
    print("- Suricata integration for signature-based detection")
    print("- Hybrid decoder combining both approaches")
    print("- Rich protocol metadata extraction")
    print("- Signature-based alert generation")
    print("- Support for HTTP, DNS, TLS, and other protocols")


if __name__ == "__main__":
    asyncio.run(main())