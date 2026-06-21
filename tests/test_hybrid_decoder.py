"""
Unit tests for HybridDecoder implementation.
"""

import pytest
import asyncio
from datetime import datetime
from unittest.mock import Mock, patch, AsyncMock

from ai_iot_ids.decoders.hybrid_decoder import HybridDecoder, HybridDecoderError
from ai_iot_ids.decoders.zeek_decoder import ZeekDecoder
from ai_iot_ids.decoders.suricata_decoder import SuricataDecoder
from ai_iot_ids.interfaces.protocol_decoder import ProtocolType, ProtocolMetadata
from ai_iot_ids.interfaces.packet_capture import RawPacket


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


@pytest.fixture
def sample_metadata():
    """Create sample protocol metadata for testing."""
    return [
        ProtocolMetadata(
            protocol=ProtocolType.HTTP,
            timestamp=datetime.now(),
            source_ip="192.168.1.100",
            destination_ip="192.168.1.1",
            source_port=12345,
            destination_port=80,
            http_method="GET",
            http_uri="/index.html",
            payload_size=1024
        ),
        ProtocolMetadata(
            protocol=ProtocolType.DNS,
            timestamp=datetime.now(),
            source_ip="192.168.1.100",
            destination_ip="8.8.8.8",
            source_port=54321,
            destination_port=53,
            dns_query="example.com",
            dns_query_type="A"
        )
    ]


class TestHybridDecoder:
    """Test cases for HybridDecoder."""
    
    def test_initialization_both_mode(self):
        """Test initialization in 'both' mode."""
        decoder = HybridDecoder(mode="both")
        
        assert decoder.mode == "both"
        assert decoder.zeek_decoder is not None
        assert decoder.suricata_decoder is not None
        assert isinstance(decoder.zeek_decoder, ZeekDecoder)
        assert isinstance(decoder.suricata_decoder, SuricataDecoder)
    
    def test_initialization_zeek_only_mode(self):
        """Test initialization in 'zeek' mode."""
        decoder = HybridDecoder(mode="zeek")
        
        assert decoder.mode == "zeek"
        assert decoder.zeek_decoder is not None
        assert decoder.suricata_decoder is None
    
    def test_initialization_suricata_only_mode(self):
        """Test initialization in 'suricata' mode."""
        decoder = HybridDecoder(mode="suricata")
        
        assert decoder.mode == "suricata"
        assert decoder.zeek_decoder is None
        assert decoder.suricata_decoder is not None
    
    def test_initialization_fallback_mode(self):
        """Test initialization in 'fallback' mode."""
        decoder = HybridDecoder(mode="fallback", primary_decoder="suricata")
        
        assert decoder.mode == "fallback"
        assert decoder.primary_decoder == "suricata"
        assert decoder.zeek_decoder is not None
        assert decoder.suricata_decoder is not None
    
    def test_initialization_invalid_mode(self):
        """Test initialization with invalid mode."""
        with pytest.raises(HybridDecoderError, match="Invalid mode"):
            HybridDecoder(mode="invalid")
    
    def test_initialization_invalid_primary_decoder(self):
        """Test initialization with invalid primary decoder."""
        with pytest.raises(HybridDecoderError, match="Invalid primary decoder"):
            HybridDecoder(mode="fallback", primary_decoder="invalid")
    
    @pytest.mark.asyncio
    async def test_initialize_success(self):
        """Test successful initialization of hybrid decoder."""
        decoder = HybridDecoder(mode="both")
        
        # Mock successful initialization of both decoders
        with patch.object(decoder.zeek_decoder, 'initialize', new_callable=AsyncMock) as mock_zeek_init:
            with patch.object(decoder.suricata_decoder, 'initialize', new_callable=AsyncMock) as mock_suricata_init:
                with patch.object(decoder.zeek_decoder, 'is_initialized', return_value=True):
                    with patch.object(decoder.suricata_decoder, 'is_initialized', return_value=True):
                        
                        await decoder.initialize()
                        
                        assert decoder.is_initialized()
                        mock_zeek_init.assert_called_once()
                        mock_suricata_init.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_initialize_no_decoders_success(self):
        """Test initialization failure when no decoders initialize successfully."""
        decoder = HybridDecoder(mode="both")
        
        # Mock failed initialization of both decoders
        with patch.object(decoder.zeek_decoder, 'initialize', new_callable=AsyncMock):
            with patch.object(decoder.suricata_decoder, 'initialize', new_callable=AsyncMock):
                with patch.object(decoder.zeek_decoder, 'is_initialized', return_value=False):
                    with patch.object(decoder.suricata_decoder, 'is_initialized', return_value=False):
                        
                        with pytest.raises(HybridDecoderError, match="No decoders initialized successfully"):
                            await decoder.initialize()
    
    @pytest.mark.asyncio
    async def test_start_stop_lifecycle(self):
        """Test start and stop lifecycle."""
        decoder = HybridDecoder(mode="both")
        
        # Mock decoder lifecycle methods
        with patch.object(decoder.zeek_decoder, 'initialize', new_callable=AsyncMock):
            with patch.object(decoder.suricata_decoder, 'initialize', new_callable=AsyncMock):
                with patch.object(decoder.zeek_decoder, 'is_initialized', return_value=True):
                    with patch.object(decoder.suricata_decoder, 'is_initialized', return_value=True):
                        with patch.object(decoder.zeek_decoder, 'start', new_callable=AsyncMock) as mock_zeek_start:
                            with patch.object(decoder.suricata_decoder, 'start', new_callable=AsyncMock) as mock_suricata_start:
                                with patch.object(decoder.zeek_decoder, 'stop', new_callable=AsyncMock) as mock_zeek_stop:
                                    with patch.object(decoder.suricata_decoder, 'stop', new_callable=AsyncMock) as mock_suricata_stop:
                                        with patch.object(decoder.zeek_decoder, 'is_running', return_value=True):
                                            with patch.object(decoder.suricata_decoder, 'is_running', return_value=True):
                                                
                                                # Test start
                                                await decoder.start()
                                                assert decoder.is_running()
                                                mock_zeek_start.assert_called_once()
                                                mock_suricata_start.assert_called_once()
                                                
                                                # Test stop
                                                await decoder.stop()
                                                assert not decoder.is_running()
                                                mock_zeek_stop.assert_called_once()
                                                mock_suricata_stop.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_decode_packets_batch_both_mode(self, sample_packets, sample_metadata):
        """Test packet decoding in 'both' mode."""
        decoder = HybridDecoder(mode="both", merge_metadata=False)
        decoder._running = True
        
        # Mock decoder responses
        zeek_metadata = [sample_metadata[0]]  # HTTP metadata
        suricata_metadata = [sample_metadata[1]]  # DNS metadata
        
        with patch.object(decoder.zeek_decoder, 'is_running', return_value=True):
            with patch.object(decoder.suricata_decoder, 'is_running', return_value=True):
                with patch.object(decoder.zeek_decoder, 'decode_packets_batch', new_callable=AsyncMock, return_value=zeek_metadata):
                    with patch.object(decoder.suricata_decoder, 'decode_packets_batch', new_callable=AsyncMock, return_value=suricata_metadata):
                        
                        result = await decoder.decode_packets_batch(sample_packets)
                        
                        # Should return combined results (Suricata first)
                        assert len(result) == 2
                        assert result[0] == sample_metadata[1]  # DNS from Suricata
                        assert result[1] == sample_metadata[0]  # HTTP from Zeek
    
    @pytest.mark.asyncio
    async def test_decode_packets_batch_zeek_only_mode(self, sample_packets, sample_metadata):
        """Test packet decoding in 'zeek' mode."""
        decoder = HybridDecoder(mode="zeek")
        decoder._running = True
        
        with patch.object(decoder.zeek_decoder, 'is_running', return_value=True):
            with patch.object(decoder.zeek_decoder, 'decode_packets_batch', new_callable=AsyncMock, return_value=sample_metadata):
                
                result = await decoder.decode_packets_batch(sample_packets)
                
                assert len(result) == 2
                assert result == sample_metadata
    
    @pytest.mark.asyncio
    async def test_decode_packets_batch_suricata_only_mode(self, sample_packets, sample_metadata):
        """Test packet decoding in 'suricata' mode."""
        decoder = HybridDecoder(mode="suricata")
        decoder._running = True
        
        with patch.object(decoder.suricata_decoder, 'is_running', return_value=True):
            with patch.object(decoder.suricata_decoder, 'decode_packets_batch', new_callable=AsyncMock, return_value=sample_metadata):
                
                result = await decoder.decode_packets_batch(sample_packets)
                
                assert len(result) == 2
                assert result == sample_metadata
    
    @pytest.mark.asyncio
    async def test_decode_packets_batch_fallback_mode_success(self, sample_packets, sample_metadata):
        """Test packet decoding in 'fallback' mode with primary decoder success."""
        decoder = HybridDecoder(mode="fallback", primary_decoder="suricata")
        decoder._running = True
        
        with patch.object(decoder.suricata_decoder, 'is_running', return_value=True):
            with patch.object(decoder.suricata_decoder, 'decode_packets_batch', new_callable=AsyncMock, return_value=sample_metadata):
                
                result = await decoder.decode_packets_batch(sample_packets)
                
                assert len(result) == 2
                assert result == sample_metadata
    
    @pytest.mark.asyncio
    async def test_decode_packets_batch_fallback_mode_fallback(self, sample_packets, sample_metadata):
        """Test packet decoding in 'fallback' mode with primary decoder failure."""
        decoder = HybridDecoder(mode="fallback", primary_decoder="suricata")
        decoder._running = True
        
        with patch.object(decoder.suricata_decoder, 'is_running', return_value=True):
            with patch.object(decoder.zeek_decoder, 'is_running', return_value=True):
                with patch.object(decoder.suricata_decoder, 'decode_packets_batch', new_callable=AsyncMock, side_effect=Exception("Primary failed")):
                    with patch.object(decoder.zeek_decoder, 'decode_packets_batch', new_callable=AsyncMock, return_value=sample_metadata):
                        
                        result = await decoder.decode_packets_batch(sample_packets)
                        
                        assert len(result) == 2
                        assert result == sample_metadata
                        assert decoder._decoder_failures["suricata"] == 1
    
    @pytest.mark.asyncio
    async def test_decode_packets_batch_fallback_mode_all_fail(self, sample_packets):
        """Test packet decoding in 'fallback' mode with all decoders failing."""
        decoder = HybridDecoder(mode="fallback", primary_decoder="suricata")
        decoder._running = True
        
        with patch.object(decoder.suricata_decoder, 'is_running', return_value=True):
            with patch.object(decoder.zeek_decoder, 'is_running', return_value=True):
                with patch.object(decoder.suricata_decoder, 'decode_packets_batch', new_callable=AsyncMock, side_effect=Exception("Primary failed")):
                    with patch.object(decoder.zeek_decoder, 'decode_packets_batch', new_callable=AsyncMock, side_effect=Exception("Secondary failed")):
                        
                        with pytest.raises(HybridDecoderError, match="All decoders failed"):
                            await decoder.decode_packets_batch(sample_packets)
                        
                        assert decoder._decoder_failures["suricata"] == 1
                        assert decoder._decoder_failures["zeek"] == 1
    
    @pytest.mark.asyncio
    async def test_decode_packets_batch_not_running(self, sample_packets):
        """Test decode_packets_batch when decoder is not running."""
        decoder = HybridDecoder(mode="both")
        
        with pytest.raises(HybridDecoderError, match="Decoder not running"):
            await decoder.decode_packets_batch(sample_packets)
    
    @pytest.mark.asyncio
    async def test_decode_packets_batch_empty_list(self):
        """Test decode_packets_batch with empty packet list."""
        decoder = HybridDecoder(mode="both")
        decoder._running = True
        
        result = await decoder.decode_packets_batch([])
        assert result == []
    
    @pytest.mark.asyncio
    async def test_get_supported_protocols(self):
        """Test getting combined supported protocols."""
        decoder = HybridDecoder(mode="both")
        
        zeek_protocols = [ProtocolType.HTTP, ProtocolType.DNS, ProtocolType.TLS]
        suricata_protocols = [ProtocolType.HTTP, ProtocolType.SSH, ProtocolType.DHCP]
        
        with patch.object(decoder.zeek_decoder, 'is_initialized', return_value=True):
            with patch.object(decoder.suricata_decoder, 'is_initialized', return_value=True):
                with patch.object(decoder.zeek_decoder, 'get_supported_protocols', new_callable=AsyncMock, return_value=zeek_protocols):
                    with patch.object(decoder.suricata_decoder, 'get_supported_protocols', new_callable=AsyncMock, return_value=suricata_protocols):
                        
                        protocols = await decoder.get_supported_protocols()
                        
                        # Should contain union of both sets
                        expected = set(zeek_protocols + suricata_protocols)
                        assert set(protocols) == expected
    
    @pytest.mark.asyncio
    async def test_get_decoder_statistics(self):
        """Test getting combined decoder statistics."""
        decoder = HybridDecoder(mode="both")
        decoder._packets_processed = 100
        decoder._alerts_generated = 5
        
        zeek_stats = {"packets_processed": 50, "rule_count": 10}
        suricata_stats = {"packets_processed": 50, "rule_count": 20}
        
        with patch.object(decoder.zeek_decoder, 'is_initialized', return_value=True):
            with patch.object(decoder.suricata_decoder, 'is_initialized', return_value=True):
                with patch.object(decoder.zeek_decoder, 'get_decoder_statistics', new_callable=AsyncMock, return_value=zeek_stats):
                    with patch.object(decoder.suricata_decoder, 'get_decoder_statistics', new_callable=AsyncMock, return_value=suricata_stats):
                        
                        stats = await decoder.get_decoder_statistics()
                        
                        assert stats["packets_processed"] == 100
                        assert stats["alerts_generated"] == 5
                        assert stats["rule_count"] == 30  # Combined rule count
                        assert stats["mode"] == "both"
                        assert "zeek" in stats["active_decoders"]
                        assert "suricata" in stats["active_decoders"]
                        assert "zeek_statistics" in stats
                        assert "suricata_statistics" in stats
    
    @pytest.mark.asyncio
    async def test_load_custom_rules(self):
        """Test loading custom rules for all decoders."""
        decoder = HybridDecoder(mode="both")
        
        with patch.object(decoder.zeek_decoder, 'is_initialized', return_value=True):
            with patch.object(decoder.suricata_decoder, 'is_initialized', return_value=True):
                with patch.object(decoder.zeek_decoder, 'load_custom_rules', new_callable=AsyncMock) as mock_zeek_load:
                    with patch.object(decoder.suricata_decoder, 'load_custom_rules', new_callable=AsyncMock) as mock_suricata_load:
                        
                        await decoder.load_custom_rules("/path/to/rules")
                        
                        mock_zeek_load.assert_called_once_with("/path/to/rules")
                        mock_suricata_load.assert_called_once_with("/path/to/rules")
    
    @pytest.mark.asyncio
    async def test_enable_disable_protocol_analysis(self):
        """Test enabling and disabling protocol analysis."""
        decoder = HybridDecoder(mode="both")
        
        protocols = [ProtocolType.HTTP, ProtocolType.DNS]
        
        with patch.object(decoder.zeek_decoder, 'is_running', return_value=True):
            with patch.object(decoder.suricata_decoder, 'is_running', return_value=True):
                with patch.object(decoder.zeek_decoder, 'enable_protocol_analysis', new_callable=AsyncMock) as mock_zeek_enable:
                    with patch.object(decoder.suricata_decoder, 'enable_protocol_analysis', new_callable=AsyncMock) as mock_suricata_enable:
                        with patch.object(decoder.zeek_decoder, 'disable_protocol_analysis', new_callable=AsyncMock) as mock_zeek_disable:
                            with patch.object(decoder.suricata_decoder, 'disable_protocol_analysis', new_callable=AsyncMock) as mock_suricata_disable:
                                
                                # Test enable
                                await decoder.enable_protocol_analysis(protocols)
                                mock_zeek_enable.assert_called_once_with(protocols)
                                mock_suricata_enable.assert_called_once_with(protocols)
                                
                                # Test disable
                                await decoder.disable_protocol_analysis(protocols)
                                mock_zeek_disable.assert_called_once_with(protocols)
                                mock_suricata_disable.assert_called_once_with(protocols)
    
    def test_merge_metadata_lists(self, sample_metadata):
        """Test merging metadata lists from different decoders."""
        decoder = HybridDecoder(mode="both")
        
        # Create matching metadata with same connection info but different protocols
        zeek_meta = ProtocolMetadata(
            protocol=ProtocolType.HTTP,
            timestamp=datetime(2023, 1, 1, 12, 0, 0),
            source_ip="192.168.1.100",
            destination_ip="192.168.1.1",
            source_port=12345,
            destination_port=80,
            http_method="GET",
            http_uri="/index.html"
        )
        
        suricata_meta = ProtocolMetadata(
            protocol=ProtocolType.HTTP,
            timestamp=datetime(2023, 1, 1, 12, 0, 0),
            source_ip="192.168.1.100",
            destination_ip="192.168.1.1",
            source_port=12345,
            destination_port=80,
            http_status_code=200,
            payload_size=1024
        )
        
        zeek_list = [zeek_meta]
        suricata_list = [suricata_meta]
        
        merged = decoder._merge_metadata_lists(zeek_list, suricata_list)
        
        assert len(merged) == 1
        merged_meta = merged[0]
        
        # Should have fields from both decoders
        assert merged_meta.http_method == "GET"  # From Zeek
        assert merged_meta.http_uri == "/index.html"  # From Zeek
        assert merged_meta.http_status_code == 200  # From Suricata
        assert merged_meta.payload_size == 1024  # From Suricata
    
    def test_merge_single_metadata(self):
        """Test merging two ProtocolMetadata objects."""
        decoder = HybridDecoder(mode="both")
        
        zeek_meta = ProtocolMetadata(
            protocol=ProtocolType.HTTP,
            timestamp=datetime.now(),
            source_ip="192.168.1.100",
            destination_ip="192.168.1.1",
            source_port=12345,
            destination_port=80,
            http_method="GET",
            http_uri="/index.html"
        )
        
        suricata_meta = ProtocolMetadata(
            protocol=ProtocolType.HTTP,
            timestamp=datetime.now(),
            source_ip="192.168.1.100",
            destination_ip="192.168.1.1",
            source_port=12345,
            destination_port=80,
            http_status_code=200,
            payload_size=1024
        )
        
        merged = decoder._merge_single_metadata(zeek_meta, suricata_meta)
        
        # Should prefer Suricata for base fields
        assert merged.protocol == suricata_meta.protocol
        
        # Should have non-None values from both
        assert merged.http_method == "GET"  # From Zeek
        assert merged.http_uri == "/index.html"  # From Zeek
        assert merged.http_status_code == 200  # From Suricata
        assert merged.payload_size == 1024  # From Suricata