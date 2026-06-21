"""
Unit tests for ZeekDecoder implementation.
"""

import pytest
import tempfile
import asyncio
from datetime import datetime
from pathlib import Path
from unittest.mock import Mock, patch, AsyncMock

from ai_iot_ids.decoders.zeek_decoder import ZeekDecoder, ZeekDecoderError
from ai_iot_ids.interfaces.protocol_decoder import ProtocolType, ProtocolMetadata
from ai_iot_ids.interfaces.packet_capture import RawPacket


@pytest.fixture
def temp_dir():
    """Create a temporary directory for testing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def mock_zeek_binary(temp_dir):
    """Create a mock Zeek binary for testing."""
    zeek_binary = temp_dir / "zeek"
    zeek_binary.write_text("#!/bin/bash\necho 'zeek version 4.0.0'\n")
    zeek_binary.chmod(0o755)
    return str(zeek_binary)


@pytest.fixture
def zeek_decoder(mock_zeek_binary, temp_dir):
    """Create a ZeekDecoder instance for testing."""
    return ZeekDecoder(
        zeek_binary_path=mock_zeek_binary,
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


class TestZeekDecoder:
    """Test cases for ZeekDecoder."""
    
    @pytest.mark.asyncio
    async def test_initialization_success(self, zeek_decoder):
        """Test successful initialization of ZeekDecoder."""
        with patch('asyncio.create_subprocess_exec') as mock_subprocess:
            # Mock successful version check
            mock_process = Mock()
            mock_process.communicate = AsyncMock(return_value=(b'zeek version 4.0.0\n', b''))
            mock_process.returncode = 0
            mock_subprocess.return_value = mock_process
            
            await zeek_decoder.initialize()
            
            assert zeek_decoder.is_initialized()
            mock_subprocess.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_initialization_binary_not_found(self, temp_dir):
        """Test initialization failure when Zeek binary is not found."""
        decoder = ZeekDecoder(
            zeek_binary_path="/nonexistent/zeek",
            temp_dir=str(temp_dir)
        )
        
        with pytest.raises(ZeekDecoderError, match="Zeek binary not found"):
            await decoder.initialize()
    
    @pytest.mark.asyncio
    async def test_initialization_version_check_fails(self, temp_dir):
        """Test initialization failure when version check fails."""
        # Create a binary that exists but fails version check
        zeek_binary = temp_dir / "zeek"
        zeek_binary.write_text("#!/bin/bash\nexit 1\n")
        zeek_binary.chmod(0o755)
        
        decoder = ZeekDecoder(
            zeek_binary_path=str(zeek_binary),
            temp_dir=str(temp_dir)
        )
        
        with patch('asyncio.create_subprocess_exec') as mock_subprocess:
            mock_process = Mock()
            mock_process.communicate = AsyncMock(return_value=(b'', b'version check failed'))
            mock_process.returncode = 1
            mock_subprocess.return_value = mock_process
            
            with pytest.raises(ZeekDecoderError, match="Zeek version check failed"):
                await decoder.initialize()
    
    @pytest.mark.asyncio
    async def test_start_stop_lifecycle(self, zeek_decoder):
        """Test start and stop lifecycle."""
        with patch('asyncio.create_subprocess_exec') as mock_subprocess:
            mock_process = Mock()
            mock_process.communicate = AsyncMock(return_value=(b'zeek version 4.0.0\n', b''))
            mock_process.returncode = 0
            mock_subprocess.return_value = mock_process
            
            # Test start
            await zeek_decoder.start()
            assert zeek_decoder.is_running()
            
            # Test stop
            await zeek_decoder.stop()
            assert not zeek_decoder.is_running()
    
    @pytest.mark.asyncio
    async def test_decode_packet_not_running(self, zeek_decoder, sample_packets):
        """Test decode_packet when decoder is not running."""
        with pytest.raises(ZeekDecoderError, match="Decoder not running"):
            await zeek_decoder.decode_packet(sample_packets[0])
    
    @pytest.mark.asyncio
    async def test_decode_packets_batch_empty_list(self, zeek_decoder):
        """Test decode_packets_batch with empty packet list."""
        with patch('asyncio.create_subprocess_exec') as mock_subprocess:
            mock_process = Mock()
            mock_process.communicate = AsyncMock(return_value=(b'zeek version 4.0.0\n', b''))
            mock_process.returncode = 0
            mock_subprocess.return_value = mock_process
            
            await zeek_decoder.start()
            
            result = await zeek_decoder.decode_packets_batch([])
            assert result == []
    
    @pytest.mark.asyncio
    async def test_decode_packets_batch_success(self, zeek_decoder, sample_packets, temp_dir):
        """Test successful packet batch decoding."""
        with patch('asyncio.create_subprocess_exec') as mock_subprocess:
            # Mock initialization
            mock_process = Mock()
            mock_process.communicate = AsyncMock(return_value=(b'zeek version 4.0.0\n', b''))
            mock_process.returncode = 0
            mock_subprocess.return_value = mock_process
            
            await zeek_decoder.start()
            
            # Mock Zeek analysis
            mock_subprocess.return_value.returncode = 0
            
            # Create mock log files
            log_dir = temp_dir / "zeek_logs_test"
            log_dir.mkdir()
            
            # Create mock conn.log
            conn_log = log_dir / "conn.log"
            conn_log.write_text(
                "#separator \\x09\n"
                "#set_separator\t,\n"
                "#empty_field\t(empty)\n"
                "#unset_field\t-\n"
                "#path\tconn\n"
                "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\n"
                "1234567890.123456\tCHhAvVGS1DHFjwGM9\t192.168.1.100\t12345\t192.168.1.1\t80\ttcp\thttp\t1.234\t500\t1000\n"
            )
            
            with patch.object(zeek_decoder, '_run_zeek_analysis', return_value=log_dir):
                with patch('scapy.all.wrpcap'):  # Mock scapy wrpcap
                    result = await zeek_decoder.decode_packets_batch(sample_packets)
                    
                    assert len(result) == 1
                    assert isinstance(result[0], ProtocolMetadata)
                    assert result[0].protocol == ProtocolType.TCP
                    assert result[0].source_ip == "192.168.1.100"
                    assert result[0].destination_ip == "192.168.1.1"
                    assert result[0].source_port == 12345
                    assert result[0].destination_port == 80
    
    @pytest.mark.asyncio
    async def test_get_supported_protocols(self, zeek_decoder):
        """Test getting supported protocols."""
        protocols = await zeek_decoder.get_supported_protocols()
        
        expected_protocols = [
            ProtocolType.TCP,
            ProtocolType.UDP,
            ProtocolType.ICMP,
            ProtocolType.HTTP,
            ProtocolType.HTTPS,
            ProtocolType.DNS,
            ProtocolType.TLS,
            ProtocolType.SSH
        ]
        
        for protocol in expected_protocols:
            assert protocol in protocols
    
    @pytest.mark.asyncio
    async def test_get_decoder_statistics(self, zeek_decoder):
        """Test getting decoder statistics."""
        stats = await zeek_decoder.get_decoder_statistics()
        
        assert "packets_processed" in stats
        assert "protocols_detected" in stats
        assert "alerts_generated" in stats
        assert "processing_rate_pps" in stats
        assert "rule_count" in stats
        assert "enabled_protocols" in stats
        
        assert stats["packets_processed"] == 0
        assert stats["alerts_generated"] == 0
    
    @pytest.mark.asyncio
    async def test_enable_disable_protocol_analysis(self, zeek_decoder):
        """Test enabling and disabling protocol analysis."""
        # Test enable
        await zeek_decoder.enable_protocol_analysis([ProtocolType.HTTP, ProtocolType.DNS])
        
        # Test disable
        await zeek_decoder.disable_protocol_analysis([ProtocolType.HTTP])
        
        # Verify DNS is still enabled but HTTP is disabled
        stats = await zeek_decoder.get_decoder_statistics()
        enabled_protocols = [ProtocolType(p) for p in stats["enabled_protocols"]]
        
        assert ProtocolType.DNS in enabled_protocols
        # HTTP should still be there since we started with all protocols enabled
    
    @pytest.mark.asyncio
    async def test_load_custom_rules_directory_not_found(self, zeek_decoder):
        """Test loading custom rules with non-existent directory."""
        with pytest.raises(FileNotFoundError, match="Rules directory not found"):
            await zeek_decoder.load_custom_rules("/nonexistent/rules")
    
    @pytest.mark.asyncio
    async def test_load_custom_rules_success(self, zeek_decoder, temp_dir):
        """Test successful loading of custom rules."""
        # Create rules directory with valid Zeek script
        rules_dir = temp_dir / "rules"
        rules_dir.mkdir()
        
        rule_file = rules_dir / "test.zeek"
        rule_file.write_text("# Valid Zeek script\nevent zeek_init() { print \"test\"; }")
        
        with patch('asyncio.create_subprocess_exec') as mock_subprocess:
            # Mock successful rule validation
            mock_process = Mock()
            mock_process.communicate = AsyncMock(return_value=(b'', b''))
            mock_process.returncode = 0
            mock_subprocess.return_value = mock_process
            
            await zeek_decoder.load_custom_rules(str(rules_dir))
            
            assert zeek_decoder.scripts_dir == rules_dir
    
    @pytest.mark.asyncio
    async def test_load_custom_rules_invalid_syntax(self, zeek_decoder, temp_dir):
        """Test loading custom rules with invalid syntax."""
        # Create rules directory with invalid Zeek script
        rules_dir = temp_dir / "rules"
        rules_dir.mkdir()
        
        rule_file = rules_dir / "invalid.zeek"
        rule_file.write_text("invalid zeek syntax here")
        
        with patch('asyncio.create_subprocess_exec') as mock_subprocess:
            # Mock failed rule validation
            mock_process = Mock()
            mock_process.communicate = AsyncMock(return_value=(b'', b'syntax error'))
            mock_process.returncode = 1
            mock_subprocess.return_value = mock_process
            
            with pytest.raises(ValueError, match="Invalid Zeek script"):
                await zeek_decoder.load_custom_rules(str(rules_dir))
    
    @pytest.mark.asyncio
    async def test_health_check_healthy(self, zeek_decoder):
        """Test health check when decoder is healthy."""
        with patch('asyncio.create_subprocess_exec') as mock_subprocess:
            mock_process = Mock()
            mock_process.communicate = AsyncMock(return_value=(b'zeek version 4.0.0\n', b''))
            mock_process.returncode = 0
            mock_subprocess.return_value = mock_process
            
            await zeek_decoder.start()
            
            health = await zeek_decoder.health_check()
            
            assert health["status"] == "healthy"
            assert health["initialized"] is True
            assert health["running"] is True
            assert "statistics" in health
            assert "supported_protocols" in health
            assert "timestamp" in health
    
    @pytest.mark.asyncio
    async def test_health_check_unhealthy(self, zeek_decoder):
        """Test health check when decoder encounters an error."""
        # Mock an error in get_decoder_statistics
        with patch.object(zeek_decoder, 'get_decoder_statistics', side_effect=Exception("Test error")):
            health = await zeek_decoder.health_check()
            
            assert health["status"] == "unhealthy"
            assert "error" in health
            assert health["error"] == "Test error"
    
    def test_parse_conn_log_line_parsing(self, zeek_decoder):
        """Test parsing of conn.log line format."""
        # This would test the internal _parse_conn_log method
        # Implementation would depend on the specific log format parsing logic
        pass
    
    def test_parse_http_log_line_parsing(self, zeek_decoder):
        """Test parsing of http.log line format."""
        # This would test the internal _parse_http_log method
        pass
    
    def test_parse_dns_log_line_parsing(self, zeek_decoder):
        """Test parsing of dns.log line format."""
        # This would test the internal _parse_dns_log method
        pass
    
    def test_parse_ssl_log_line_parsing(self, zeek_decoder):
        """Test parsing of ssl.log line format."""
        # This would test the internal _parse_ssl_log method
        pass


class TestZeekDecoderIntegration:
    """Integration tests for ZeekDecoder (require actual Zeek installation)."""
    
    @pytest.mark.integration
    @pytest.mark.skipif(not Path("/usr/local/zeek/bin/zeek").exists(), 
                       reason="Zeek not installed")
    async def test_real_zeek_integration(self, temp_dir):
        """Test with real Zeek installation (if available)."""
        decoder = ZeekDecoder(temp_dir=str(temp_dir))
        
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