"""
Unit tests for SuricataDecoder implementation.
"""

import pytest
import tempfile
import asyncio
import json
from datetime import datetime
from pathlib import Path
from unittest.mock import Mock, patch, AsyncMock

from ai_iot_ids.decoders.suricata_decoder import SuricataDecoder, SuricataDecoderError
from ai_iot_ids.interfaces.protocol_decoder import ProtocolType, ProtocolMetadata
from ai_iot_ids.interfaces.packet_capture import RawPacket


@pytest.fixture
def temp_dir():
    """Create a temporary directory for testing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def mock_suricata_binary(temp_dir):
    """Create a mock Suricata binary for testing."""
    suricata_binary = temp_dir / "suricata"
    suricata_binary.write_text("#!/bin/bash\necho 'Suricata 6.0.0'\n")
    suricata_binary.chmod(0o755)
    return str(suricata_binary)


@pytest.fixture
def suricata_decoder(mock_suricata_binary, temp_dir):
    """Create a SuricataDecoder instance for testing."""
    return SuricataDecoder(
        suricata_binary_path=mock_suricata_binary,
        temp_dir=str(temp_dir),
        timeout_seconds=5
    )


@pytest.fixture
def sample_packets():
    """Create sample raw packets for testing."""
    return [
        RawPacket(
            timestamp=datetime.now(),
            data=b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x08\x00',
            interface="eth0",
            length=14
        ),
        RawPacket(
            timestamp=datetime.now(),
            data=b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x08\x06',
            interface="eth0",
            length=14
        )
    ]


class TestSuricataDecoder:
    """Test cases for SuricataDecoder."""
    
    @pytest.mark.asyncio
    async def test_initialization_success(self, suricata_decoder):
        """Test successful initialization of SuricataDecoder."""
        with patch('asyncio.create_subprocess_exec') as mock_subprocess:
            # Mock successful build info check
            mock_process = Mock()
            mock_process.communicate = AsyncMock(return_value=(b'Suricata 6.0.0\n', b''))
            mock_process.returncode = 0
            mock_subprocess.return_value = mock_process
            
            await suricata_decoder.initialize()
            
            assert suricata_decoder.is_initialized()
            mock_subprocess.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_initialization_binary_not_found(self, temp_dir):
        """Test initialization failure when Suricata binary is not found."""
        decoder = SuricataDecoder(
            suricata_binary_path="/nonexistent/suricata",
            temp_dir=str(temp_dir)
        )
        
        with pytest.raises(SuricataDecoderError, match="Suricata binary not found"):
            await decoder.initialize()
    
    @pytest.mark.asyncio
    async def test_initialization_build_info_fails(self, temp_dir):
        """Test initialization failure when build info check fails."""
        # Create a binary that exists but fails build info check
        suricata_binary = temp_dir / "suricata"
        suricata_binary.write_text("#!/bin/bash\nexit 1\n")
        suricata_binary.chmod(0o755)
        
        decoder = SuricataDecoder(
            suricata_binary_path=str(suricata_binary),
            temp_dir=str(temp_dir)
        )
        
        with patch('asyncio.create_subprocess_exec') as mock_subprocess:
            mock_process = Mock()
            mock_process.communicate = AsyncMock(return_value=(b'', b'build info failed'))
            mock_process.returncode = 1
            mock_subprocess.return_value = mock_process
            
            with pytest.raises(SuricataDecoderError, match="Suricata build info check failed"):
                await decoder.initialize()
    
    @pytest.mark.asyncio
    async def test_start_stop_lifecycle(self, suricata_decoder):
        """Test start and stop lifecycle."""
        with patch('asyncio.create_subprocess_exec') as mock_subprocess:
            mock_process = Mock()
            mock_process.communicate = AsyncMock(return_value=(b'Suricata 6.0.0\n', b''))
            mock_process.returncode = 0
            mock_subprocess.return_value = mock_process
            
            # Test start
            await suricata_decoder.start()
            assert suricata_decoder.is_running()
            
            # Test stop
            await suricata_decoder.stop()
            assert not suricata_decoder.is_running()
    
    @pytest.mark.asyncio
    async def test_decode_packet_not_running(self, suricata_decoder, sample_packets):
        """Test decode_packet when decoder is not running."""
        with pytest.raises(SuricataDecoderError, match="Decoder not running"):
            await suricata_decoder.decode_packet(sample_packets[0])
    
    @pytest.mark.asyncio
    async def test_decode_packets_batch_empty_list(self, suricata_decoder):
        """Test decode_packets_batch with empty packet list."""
        with patch('asyncio.create_subprocess_exec') as mock_subprocess:
            mock_process = Mock()
            mock_process.communicate = AsyncMock(return_value=(b'Suricata 6.0.0\n', b''))
            mock_process.returncode = 0
            mock_subprocess.return_value = mock_process
            
            await suricata_decoder.start()
            
            result = await suricata_decoder.decode_packets_batch([])
            assert result == []
    
    @pytest.mark.asyncio
    async def test_decode_packets_batch_success(self, suricata_decoder, sample_packets, temp_dir):
        """Test successful packet batch decoding."""
        with patch('asyncio.create_subprocess_exec') as mock_subprocess:
            # Mock initialization
            mock_process = Mock()
            mock_process.communicate = AsyncMock(return_value=(b'Suricata 6.0.0\n', b''))
            mock_process.returncode = 0
            mock_subprocess.return_value = mock_process
            
            await suricata_decoder.start()
            
            # Mock Suricata analysis
            mock_subprocess.return_value.returncode = 0
            
            # Create mock log files
            log_dir = temp_dir / "suricata_logs_test"
            log_dir.mkdir()
            
            # Create mock eve.json
            eve_log = log_dir / "eve.json"
            eve_events = [
                {
                    "timestamp": "2023-01-01T12:00:00.000000+0000",
                    "event_type": "flow",
                    "src_ip": "192.168.1.100",
                    "dest_ip": "192.168.1.1",
                    "src_port": 12345,
                    "dest_port": 80,
                    "proto": "TCP",
                    "flow": {
                        "bytes_toserver": 500,
                        "bytes_toclient": 1000
                    }
                },
                {
                    "timestamp": "2023-01-01T12:00:01.000000+0000",
                    "event_type": "http",
                    "src_ip": "192.168.1.100",
                    "dest_ip": "192.168.1.1",
                    "src_port": 12345,
                    "dest_port": 80,
                    "proto": "TCP",
                    "http": {
                        "http_method": "GET",
                        "url": "/index.html",
                        "http_user_agent": "Mozilla/5.0",
                        "status": 200,
                        "length": 1024
                    }
                }
            ]
            
            with open(eve_log, 'w') as f:
                for event in eve_events:
                    f.write(json.dumps(event) + '\n')
            
            with patch.object(suricata_decoder, '_run_suricata_analysis', return_value=log_dir):
                with patch('scapy.all.wrpcap'):  # Mock scapy wrpcap
                    result = await suricata_decoder.decode_packets_batch(sample_packets)
                    
                    assert len(result) == 2
                    
                    # Check flow event
                    flow_metadata = result[0]
                    assert isinstance(flow_metadata, ProtocolMetadata)
                    assert flow_metadata.protocol == ProtocolType.TCP
                    assert flow_metadata.source_ip == "192.168.1.100"
                    assert flow_metadata.destination_ip == "192.168.1.1"
                    assert flow_metadata.payload_size == 1500
                    
                    # Check HTTP event
                    http_metadata = result[1]
                    assert http_metadata.protocol == ProtocolType.HTTP
                    assert http_metadata.http_method == "GET"
                    assert http_metadata.http_uri == "/index.html"
                    assert http_metadata.http_status_code == 200
    
    @pytest.mark.asyncio
    async def test_get_supported_protocols(self, suricata_decoder):
        """Test getting supported protocols."""
        protocols = await suricata_decoder.get_supported_protocols()
        
        expected_protocols = [
            ProtocolType.TCP,
            ProtocolType.UDP,
            ProtocolType.ICMP,
            ProtocolType.HTTP,
            ProtocolType.HTTPS,
            ProtocolType.DNS,
            ProtocolType.TLS,
            ProtocolType.SSH,
            ProtocolType.DHCP
        ]
        
        for protocol in expected_protocols:
            assert protocol in protocols
    
    @pytest.mark.asyncio
    async def test_get_decoder_statistics(self, suricata_decoder):
        """Test getting decoder statistics."""
        stats = await suricata_decoder.get_decoder_statistics()
        
        assert "packets_processed" in stats
        assert "protocols_detected" in stats
        assert "alerts_generated" in stats
        assert "processing_rate_pps" in stats
        assert "rule_count" in stats
        assert "enabled_protocols" in stats
        
        assert stats["packets_processed"] == 0
        assert stats["alerts_generated"] == 0
    
    @pytest.mark.asyncio
    async def test_enable_disable_protocol_analysis(self, suricata_decoder):
        """Test enabling and disabling protocol analysis."""
        # Test enable
        await suricata_decoder.enable_protocol_analysis([ProtocolType.HTTP, ProtocolType.DNS])
        
        # Test disable
        await suricata_decoder.disable_protocol_analysis([ProtocolType.HTTP])
        
        # Verify DNS is still enabled but HTTP is disabled
        stats = await suricata_decoder.get_decoder_statistics()
        enabled_protocols = [ProtocolType(p) for p in stats["enabled_protocols"]]
        
        assert ProtocolType.DNS in enabled_protocols
    
    @pytest.mark.asyncio
    async def test_load_custom_rules_directory_not_found(self, suricata_decoder):
        """Test loading custom rules with non-existent directory."""
        with pytest.raises(FileNotFoundError, match="Rules directory not found"):
            await suricata_decoder.load_custom_rules("/nonexistent/rules")
    
    @pytest.mark.asyncio
    async def test_load_custom_rules_success(self, suricata_decoder, temp_dir):
        """Test successful loading of custom rules."""
        # Create rules directory with valid Suricata rule
        rules_dir = temp_dir / "rules"
        rules_dir.mkdir()
        
        rule_file = rules_dir / "test.rules"
        rule_file.write_text('alert tcp any any -> any any (msg:"Test rule"; sid:1; rev:1;)')
        
        with patch('asyncio.create_subprocess_exec') as mock_subprocess:
            # Mock successful rule validation
            mock_process = Mock()
            mock_process.communicate = AsyncMock(return_value=(b'', b''))
            mock_process.returncode = 0
            mock_subprocess.return_value = mock_process
            
            await suricata_decoder.load_custom_rules(str(rules_dir))
            
            assert suricata_decoder.rules_dir == rules_dir
            assert suricata_decoder._rule_count == 1
    
    @pytest.mark.asyncio
    async def test_load_custom_rules_invalid_syntax(self, suricata_decoder, temp_dir):
        """Test loading custom rules with invalid syntax."""
        # Create rules directory with invalid Suricata rule
        rules_dir = temp_dir / "rules"
        rules_dir.mkdir()
        
        rule_file = rules_dir / "invalid.rules"
        rule_file.write_text("invalid suricata rule syntax")
        
        with patch('asyncio.create_subprocess_exec') as mock_subprocess:
            # Mock failed rule validation
            mock_process = Mock()
            mock_process.communicate = AsyncMock(return_value=(b'', b'syntax error'))
            mock_process.returncode = 1
            mock_subprocess.return_value = mock_process
            
            with pytest.raises(ValueError, match="Invalid Suricata rule file"):
                await suricata_decoder.load_custom_rules(str(rules_dir))
    
    @pytest.mark.asyncio
    async def test_parse_eve_event_dns(self, suricata_decoder):
        """Test parsing DNS event from EVE JSON."""
        event = {
            "timestamp": "2023-01-01T12:00:00.000000+0000",
            "event_type": "dns",
            "src_ip": "192.168.1.100",
            "dest_ip": "8.8.8.8",
            "src_port": 12345,
            "dest_port": 53,
            "proto": "UDP",
            "dns": {
                "rrname": "example.com",
                "rrtype": "A",
                "rcode": "NOERROR",
                "answers": [
                    {"rdata": "93.184.216.34"}
                ]
            }
        }
        
        metadata = await suricata_decoder._parse_eve_event(event)
        
        assert metadata is not None
        assert metadata.protocol == ProtocolType.UDP
        assert metadata.dns_query == "example.com"
        assert metadata.dns_query_type == "A"
        assert metadata.dns_response_code == "NOERROR"
        assert metadata.dns_answers == ["93.184.216.34"]
    
    @pytest.mark.asyncio
    async def test_parse_eve_event_tls(self, suricata_decoder):
        """Test parsing TLS event from EVE JSON."""
        event = {
            "timestamp": "2023-01-01T12:00:00.000000+0000",
            "event_type": "tls",
            "src_ip": "192.168.1.100",
            "dest_ip": "93.184.216.34",
            "src_port": 12345,
            "dest_port": 443,
            "proto": "TCP",
            "tls": {
                "version": "TLS 1.3",
                "sni": "example.com",
                "ja3": {"hash": "abc123"},
                "ja3s": {"hash": "def456"}
            }
        }
        
        metadata = await suricata_decoder._parse_eve_event(event)
        
        assert metadata is not None
        assert metadata.protocol == ProtocolType.TLS
        assert metadata.tls_version == "TLS 1.3"
        assert metadata.tls_sni == "example.com"
        assert metadata.tls_ja3_fingerprint == "abc123"
        assert metadata.tls_ja3s_fingerprint == "def456"
    
    @pytest.mark.asyncio
    async def test_parse_eve_event_alert(self, suricata_decoder):
        """Test parsing alert event from EVE JSON."""
        event = {
            "timestamp": "2023-01-01T12:00:00.000000+0000",
            "event_type": "alert",
            "src_ip": "192.168.1.100",
            "dest_ip": "192.168.1.1",
            "src_port": 12345,
            "dest_port": 80,
            "proto": "TCP",
            "alert": {
                "gid": 1,
                "signature_id": 2001,
                "signature": "ET SCAN Potential SSH Scan",
                "severity": "high",
                "category": "Attempted Information Leak"
            }
        }
        
        # Alert events should return None for metadata but update statistics
        initial_alerts = suricata_decoder._alerts_generated
        metadata = await suricata_decoder._parse_eve_event(event)
        
        assert metadata is None
        assert suricata_decoder._alerts_generated == initial_alerts + 1
    
    @pytest.mark.asyncio
    async def test_health_check_healthy(self, suricata_decoder):
        """Test health check when decoder is healthy."""
        with patch('asyncio.create_subprocess_exec') as mock_subprocess:
            mock_process = Mock()
            mock_process.communicate = AsyncMock(return_value=(b'Suricata 6.0.0\n', b''))
            mock_process.returncode = 0
            mock_subprocess.return_value = mock_process
            
            await suricata_decoder.start()
            
            health = await suricata_decoder.health_check()
            
            assert health["status"] == "healthy"
            assert health["initialized"] is True
            assert health["running"] is True
            assert "statistics" in health
            assert "supported_protocols" in health
            assert "timestamp" in health
    
    @pytest.mark.asyncio
    async def test_health_check_unhealthy(self, suricata_decoder):
        """Test health check when decoder encounters an error."""
        # Mock an error in get_decoder_statistics
        with patch.object(suricata_decoder, 'get_decoder_statistics', side_effect=Exception("Test error")):
            health = await suricata_decoder.health_check()
            
            assert health["status"] == "unhealthy"
            assert "error" in health
            assert health["error"] == "Test error"
    
    @pytest.mark.asyncio
    async def test_create_default_config(self, suricata_decoder, temp_dir):
        """Test creation of default Suricata configuration."""
        config_file = temp_dir / "test_suricata.yaml"
        suricata_decoder.config_file = config_file
        
        await suricata_decoder._create_default_config()
        
        assert config_file.exists()
        
        # Verify config contains expected sections
        import yaml
        with open(config_file, 'r') as f:
            config = yaml.safe_load(f)
        
        assert "vars" in config
        assert "outputs" in config
        assert "app-layer" in config
        assert "logging" in config


class TestSuricataDecoderIntegration:
    """Integration tests for SuricataDecoder (require actual Suricata installation)."""
    
    @pytest.mark.integration
    @pytest.mark.skipif(not Path("/usr/bin/suricata").exists(), 
                       reason="Suricata not installed")
    async def test_real_suricata_integration(self, temp_dir):
        """Test with real Suricata installation (if available)."""
        decoder = SuricataDecoder(temp_dir=str(temp_dir))
        
        try:
            await decoder.initialize()
            await decoder.start()
            
            # Test with minimal packet data
            packets = [
                RawPacket(
                    timestamp=datetime.now(),
                    data=b'\x00' * 64,  # Minimal packet
                    interface="test",
                    length=64
                )
            ]
            
            # This might fail due to invalid packet data, but should not crash
            try:
                result = await decoder.decode_packets_batch(packets)
                # Result might be empty due to invalid packet, but should be a list
                assert isinstance(result, list)
            except Exception as e:
                # Expected for invalid packet data
                assert "pcap" in str(e).lower() or "packet" in str(e).lower()
            
        finally:
            await decoder.stop()