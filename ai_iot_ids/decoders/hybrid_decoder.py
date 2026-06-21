"""
Hybrid protocol decoder implementation for the AI-driven IoT IDS system.

This module provides a concrete implementation of the ProtocolDecoderInterface
that combines both Zeek and Suricata decoders to provide comprehensive
protocol analysis and threat detection capabilities.
"""

import asyncio
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional, AsyncIterator, Union

from ..interfaces.protocol_decoder import (
    ProtocolDecoderInterface,
    ProtocolMetadata,
    ProtocolType,
    SignatureAlert
)
from ..interfaces.packet_capture import RawPacket
from ..utils.error_handling import IDSError
from .zeek_decoder import ZeekDecoder, ZeekDecoderError
from .suricata_decoder import SuricataDecoder, SuricataDecoderError


logger = logging.getLogger(__name__)


class HybridDecoderError(IDSError):
    """Hybrid decoder-specific errors."""
    pass


class HybridDecoder(ProtocolDecoderInterface):
    """
    Hybrid protocol decoder that combines Zeek and Suricata.
    
    This decoder runs both Zeek and Suricata analysis on the same packet data
    to provide comprehensive protocol analysis and signature-based detection.
    It can operate in different modes:
    - Both: Run both decoders (default)
    - Zeek-only: Use only Zeek for analysis
    - Suricata-only: Use only Suricata for analysis
    - Fallback: Try primary decoder, fallback to secondary on failure
    """
    
    def __init__(
        self,
        zeek_config: Optional[Dict[str, Any]] = None,
        suricata_config: Optional[Dict[str, Any]] = None,
        mode: str = "both",
        primary_decoder: str = "suricata",
        merge_metadata: bool = True
    ):
        """
        Initialize hybrid decoder.
        
        Args:
            zeek_config: Configuration parameters for Zeek decoder
            suricata_config: Configuration parameters for Suricata decoder
            mode: Operation mode ("both", "zeek", "suricata", "fallback")
            primary_decoder: Primary decoder for fallback mode ("zeek" or "suricata")
            merge_metadata: Whether to merge metadata from both decoders
        """
        config = {
            "zeek_config": zeek_config or {},
            "suricata_config": suricata_config or {},
            "mode": mode,
            "primary_decoder": primary_decoder,
            "merge_metadata": merge_metadata
        }
        super().__init__(config)
        self.mode = mode.lower()
        self.primary_decoder = primary_decoder.lower()
        self.merge_metadata = merge_metadata
        
        # Initialize decoders based on configuration
        self.zeek_decoder = None
        self.suricata_decoder = None
        
        if self.mode in ["both", "zeek", "fallback"]:
            zeek_config = zeek_config or {}
            self.zeek_decoder = ZeekDecoder(**zeek_config)
        
        if self.mode in ["both", "suricata", "fallback"]:
            suricata_config = suricata_config or {}
            self.suricata_decoder = SuricataDecoder(**suricata_config)
        
        # Validate configuration
        if self.mode not in ["both", "zeek", "suricata", "fallback"]:
            raise HybridDecoderError(f"Invalid mode: {self.mode}")
        
        if self.primary_decoder not in ["zeek", "suricata"]:
            raise HybridDecoderError(f"Invalid primary decoder: {self.primary_decoder}")
        
        # Statistics tracking
        self._packets_processed = 0
        self._protocols_detected = {}
        self._alerts_generated = 0
        self._decoder_failures = {"zeek": 0, "suricata": 0}
    
    async def initialize(self) -> None:
        """Initialize the hybrid decoder and its components."""
        try:
            initialization_tasks = []
            
            if self.zeek_decoder:
                initialization_tasks.append(self.zeek_decoder.initialize())
            
            if self.suricata_decoder:
                initialization_tasks.append(self.suricata_decoder.initialize())
            
            if initialization_tasks:
                await asyncio.gather(*initialization_tasks, return_exceptions=True)
            
            # Check if at least one decoder initialized successfully
            initialized_decoders = []
            if self.zeek_decoder and self.zeek_decoder.is_initialized():
                initialized_decoders.append("Zeek")
            if self.suricata_decoder and self.suricata_decoder.is_initialized():
                initialized_decoders.append("Suricata")
            
            if not initialized_decoders:
                logger.warning("No external decoders initialized successfully. Falling back to basic Scapy metadata extraction (dummy mode).")
                self.mode = "dummy"
                self._initialized = True
            else:
                logger.info(f"Hybrid decoder initialized with: {', '.join(initialized_decoders)}")
                self._initialized = True
            
        except Exception as e:
            logger.error(f"Failed to initialize hybrid decoder: {e}")
            raise HybridDecoderError(f"Initialization failed: {e}")
    
    async def start(self) -> None:
        """Start the hybrid decoder and its components."""
        if not self._initialized:
            await self.initialize()
        
        start_tasks = []
        
        if self.zeek_decoder and self.zeek_decoder.is_initialized():
            start_tasks.append(self.zeek_decoder.start())
        
        if self.suricata_decoder and self.suricata_decoder.is_initialized():
            start_tasks.append(self.suricata_decoder.start())
        
        if start_tasks:
            await asyncio.gather(*start_tasks, return_exceptions=True)
        
        self._running = True
        logger.info(f"Hybrid decoder started in {self.mode} mode")
    
    async def stop(self) -> None:
        """Stop the hybrid decoder and its components."""
        stop_tasks = []
        
        if self.zeek_decoder and self.zeek_decoder.is_running():
            stop_tasks.append(self.zeek_decoder.stop())
        
        if self.suricata_decoder and self.suricata_decoder.is_running():
            stop_tasks.append(self.suricata_decoder.stop())
        
        if stop_tasks:
            await asyncio.gather(*stop_tasks, return_exceptions=True)
        
        self._running = False
        logger.info("Hybrid decoder stopped")
    
    async def decode_packet(self, packet: RawPacket) -> Optional[ProtocolMetadata]:
        """
        Decode a single packet using the configured decoders.
        
        Args:
            packet: Raw packet data to decode
            
        Returns:
            ProtocolMetadata if packet could be decoded, None otherwise
        """
        if not self._running:
            raise HybridDecoderError("Decoder not running")
        
        # For single packet, use batch processing with size 1
        results = await self.decode_packets_batch([packet])
        return results[0] if results else None
    
    async def decode_packets_batch(self, packets: List[RawPacket]) -> List[ProtocolMetadata]:
        """
        Decode multiple packets in batch using the configured decoders.
        
        Args:
            packets: List of raw packets to decode
            
        Returns:
            List of decoded protocol metadata
        """
        if not self._running:
            raise HybridDecoderError("Decoder not running")
        
        if not packets:
            return []
        
        try:
            if self.mode == "both":
                return await self._decode_with_both_decoders(packets)
            elif self.mode == "zeek":
                return await self._decode_with_zeek(packets)
            elif self.mode == "suricata":
                return await self._decode_with_suricata(packets)
            elif self.mode == "fallback":
                return await self._decode_with_fallback(packets)
            elif self.mode == "dummy":
                return await self._decode_with_dummy(packets)
            else:
                raise HybridDecoderError(f"Unsupported mode: {self.mode}")
                
        except Exception as e:
            logger.error(f"Hybrid batch decoding failed: {e}")
            raise HybridDecoderError(f"Batch decoding failed: {e}")
    
    async def get_signature_alerts(self) -> AsyncIterator[SignatureAlert]:
        """
        Get signature-based security alerts from active decoders.
        
        Yields:
            SignatureAlert: Security alerts from Zeek and/or Suricata
        """
        alert_tasks = []
        
        if self.suricata_decoder and self.suricata_decoder.is_running():
            alert_tasks.append(self.suricata_decoder.get_signature_alerts())
        
        if self.zeek_decoder and self.zeek_decoder.is_running():
            alert_tasks.append(self.zeek_decoder.get_signature_alerts())
        
        # This is a simplified implementation - in practice, you'd want to
        # properly merge alert streams from multiple decoders
        for alert_stream in alert_tasks:
            async for alert in alert_stream:
                yield alert
    
    async def load_custom_rules(self, rules_path: str) -> None:
        """
        Load custom rules for all active decoders.
        
        Args:
            rules_path: Path to directory containing rule files
        """
        load_tasks = []
        
        if self.zeek_decoder and self.zeek_decoder.is_initialized():
            load_tasks.append(self.zeek_decoder.load_custom_rules(rules_path))
        
        if self.suricata_decoder and self.suricata_decoder.is_initialized():
            load_tasks.append(self.suricata_decoder.load_custom_rules(rules_path))
        
        if load_tasks:
            results = await asyncio.gather(*load_tasks, return_exceptions=True)
            
            # Check for any failures
            for i, result in enumerate(results):
                if isinstance(result, Exception):
                    decoder_name = "Zeek" if i == 0 else "Suricata"
                    logger.warning(f"Failed to load rules for {decoder_name}: {result}")
    
    async def reload_rules(self) -> None:
        """Reload rules for all active decoders."""
        reload_tasks = []
        
        if self.zeek_decoder and self.zeek_decoder.is_running():
            reload_tasks.append(self.zeek_decoder.reload_rules())
        
        if self.suricata_decoder and self.suricata_decoder.is_running():
            reload_tasks.append(self.suricata_decoder.reload_rules())
        
        if reload_tasks:
            await asyncio.gather(*reload_tasks, return_exceptions=True)
    
    async def get_supported_protocols(self) -> List[ProtocolType]:
        """Get combined list of protocols supported by active decoders."""
        supported_protocols = set()
        
        if self.zeek_decoder and self.zeek_decoder.is_initialized():
            zeek_protocols = await self.zeek_decoder.get_supported_protocols()
            supported_protocols.update(zeek_protocols)
        
        if self.suricata_decoder and self.suricata_decoder.is_initialized():
            suricata_protocols = await self.suricata_decoder.get_supported_protocols()
            supported_protocols.update(suricata_protocols)
        
        return list(supported_protocols)
    
    async def get_decoder_statistics(self) -> Dict[str, Any]:
        """Get combined statistics from all active decoders."""
        stats = {
            "packets_processed": self._packets_processed,
            "protocols_detected": dict(self._protocols_detected),
            "alerts_generated": self._alerts_generated,
            "processing_rate_pps": 0,
            "rule_count": 0,
            "decoder_failures": dict(self._decoder_failures),
            "mode": self.mode,
            "active_decoders": []
        }
        
        # Collect statistics from individual decoders
        if self.zeek_decoder and self.zeek_decoder.is_initialized():
            zeek_stats = await self.zeek_decoder.get_decoder_statistics()
            stats["zeek_statistics"] = zeek_stats
            stats["rule_count"] += zeek_stats.get("rule_count", 0)
            stats["active_decoders"].append("zeek")
        
        if self.suricata_decoder and self.suricata_decoder.is_initialized():
            suricata_stats = await self.suricata_decoder.get_decoder_statistics()
            stats["suricata_statistics"] = suricata_stats
            stats["rule_count"] += suricata_stats.get("rule_count", 0)
            stats["active_decoders"].append("suricata")
        
        return stats
    
    async def enable_protocol_analysis(self, protocols: List[ProtocolType]) -> None:
        """Enable analysis for specific protocols on all active decoders."""
        enable_tasks = []
        
        if self.zeek_decoder and self.zeek_decoder.is_running():
            enable_tasks.append(self.zeek_decoder.enable_protocol_analysis(protocols))
        
        if self.suricata_decoder and self.suricata_decoder.is_running():
            enable_tasks.append(self.suricata_decoder.enable_protocol_analysis(protocols))
        
        if enable_tasks:
            await asyncio.gather(*enable_tasks, return_exceptions=True)
    
    async def disable_protocol_analysis(self, protocols: List[ProtocolType]) -> None:
        """Disable analysis for specific protocols on all active decoders."""
        disable_tasks = []
        
        if self.zeek_decoder and self.zeek_decoder.is_running():
            disable_tasks.append(self.zeek_decoder.disable_protocol_analysis(protocols))
        
        if self.suricata_decoder and self.suricata_decoder.is_running():
            disable_tasks.append(self.suricata_decoder.disable_protocol_analysis(protocols))
        
        if disable_tasks:
            await asyncio.gather(*disable_tasks, return_exceptions=True)
    
    async def _decode_with_both_decoders(self, packets: List[RawPacket]) -> List[ProtocolMetadata]:
        """Decode packets using both Zeek and Suricata decoders."""
        decode_tasks = []
        
        if self.zeek_decoder and self.zeek_decoder.is_running():
            decode_tasks.append(self.zeek_decoder.decode_packets_batch(packets))
        
        if self.suricata_decoder and self.suricata_decoder.is_running():
            decode_tasks.append(self.suricata_decoder.decode_packets_batch(packets))
        
        if not decode_tasks:
            return []
        
        results = await asyncio.gather(*decode_tasks, return_exceptions=True)
        
        # Process results
        zeek_metadata = []
        suricata_metadata = []
        
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                decoder_name = "zeek" if i == 0 else "suricata"
                self._decoder_failures[decoder_name] += 1
                logger.warning(f"Decoder {decoder_name} failed: {result}")
            else:
                if i == 0:  # Zeek results
                    zeek_metadata = result
                else:  # Suricata results
                    suricata_metadata = result
        
        # Merge or combine results
        if self.merge_metadata:
            return self._merge_metadata_lists(zeek_metadata, suricata_metadata)
        else:
            # Return combined list (Suricata first for signature detection priority)
            combined = suricata_metadata + zeek_metadata
            self._packets_processed += len(packets)
            return combined
    
    async def _decode_with_zeek(self, packets: List[RawPacket]) -> List[ProtocolMetadata]:
        """Decode packets using only Zeek decoder."""
        if not self.zeek_decoder or not self.zeek_decoder.is_running():
            raise HybridDecoderError("Zeek decoder not available")
        
        try:
            metadata_list = await self.zeek_decoder.decode_packets_batch(packets)
            self._packets_processed += len(packets)
            return metadata_list
        except Exception as e:
            self._decoder_failures["zeek"] += 1
            raise HybridDecoderError(f"Zeek decoding failed: {e}")
    
    async def _decode_with_suricata(self, packets: List[RawPacket]) -> List[ProtocolMetadata]:
        """Decode packets using only Suricata decoder."""
        if not self.suricata_decoder or not self.suricata_decoder.is_running():
            raise HybridDecoderError("Suricata decoder not available")
        
        try:
            metadata_list = await self.suricata_decoder.decode_packets_batch(packets)
            self._packets_processed += len(packets)
            return metadata_list
        except Exception as e:
            self._decoder_failures["suricata"] += 1
            raise HybridDecoderError(f"Suricata decoding failed: {e}")
    
    async def _decode_with_fallback(self, packets: List[RawPacket]) -> List[ProtocolMetadata]:
        """Decode packets using fallback strategy."""
        primary = self.suricata_decoder if self.primary_decoder == "suricata" else self.zeek_decoder
        secondary = self.zeek_decoder if self.primary_decoder == "suricata" else self.suricata_decoder
        
        # Try primary decoder first
        if primary and primary.is_running():
            try:
                metadata_list = await primary.decode_packets_batch(packets)
                self._packets_processed += len(packets)
                return metadata_list
            except Exception as e:
                self._decoder_failures[self.primary_decoder] += 1
                logger.warning(f"Primary decoder ({self.primary_decoder}) failed: {e}")
        
        # Fallback to secondary decoder
        if secondary and secondary.is_running():
            try:
                fallback_decoder = "zeek" if self.primary_decoder == "suricata" else "suricata"
                logger.info(f"Falling back to {fallback_decoder} decoder")
                metadata_list = await secondary.decode_packets_batch(packets)
                self._packets_processed += len(packets)
                return metadata_list
            except Exception as e:
                fallback_decoder = "zeek" if self.primary_decoder == "suricata" else "suricata"
                self._decoder_failures[fallback_decoder] += 1
                logger.error(f"Fallback decoder ({fallback_decoder}) also failed: {e}")
        
        raise HybridDecoderError("All decoders failed")
    
    async def _decode_with_dummy(self, packets: List[RawPacket]) -> List[ProtocolMetadata]:
        """Decode packets using basic dummy extraction from RawPacket metadata."""
        metadata_list = []
        for p in packets:
            metadata_list.append(ProtocolMetadata(
                protocol=p.protocol or "unknown",
                timestamp=p.timestamp,
                source_ip=p.source_ip,
                destination_ip=p.destination_ip,
                source_port=p.source_port,
                destination_port=p.destination_port
            ))
        self._packets_processed += len(packets)
        return metadata_list
    
    def _merge_metadata_lists(
        self, 
        zeek_metadata: List[ProtocolMetadata], 
        suricata_metadata: List[ProtocolMetadata]
    ) -> List[ProtocolMetadata]:
        """
        Merge metadata from Zeek and Suricata decoders.
        
        This is a simplified merge that combines metadata based on timestamp
        and connection 5-tuple matching.
        """
        merged = []
        
        # Create lookup for Suricata metadata
        suricata_lookup = {}
        for metadata in suricata_metadata:
            key = (
                metadata.timestamp.timestamp(),
                metadata.source_ip,
                metadata.destination_ip,
                metadata.source_port,
                metadata.destination_port,
                metadata.protocol
            )
            suricata_lookup[key] = metadata
        
        # Merge Zeek metadata with Suricata where possible
        for zeek_meta in zeek_metadata:
            key = (
                zeek_meta.timestamp.timestamp(),
                zeek_meta.source_ip,
                zeek_meta.destination_ip,
                zeek_meta.source_port,
                zeek_meta.destination_port,
                zeek_meta.protocol
            )
            
            if key in suricata_lookup:
                # Merge the metadata
                suricata_meta = suricata_lookup[key]
                merged_meta = self._merge_single_metadata(zeek_meta, suricata_meta)
                merged.append(merged_meta)
                del suricata_lookup[key]  # Remove to avoid duplicates
            else:
                merged.append(zeek_meta)
        
        # Add remaining Suricata metadata that didn't match
        merged.extend(suricata_lookup.values())
        
        self._packets_processed += len(merged)
        return merged
    
    def _merge_single_metadata(
        self, 
        zeek_meta: ProtocolMetadata, 
        suricata_meta: ProtocolMetadata
    ) -> ProtocolMetadata:
        """Merge two ProtocolMetadata objects, preferring non-None values."""
        # Start with Suricata metadata (for signature detection priority)
        merged = ProtocolMetadata(
            protocol=suricata_meta.protocol,
            timestamp=suricata_meta.timestamp,
            source_ip=suricata_meta.source_ip,
            destination_ip=suricata_meta.destination_ip,
            source_port=suricata_meta.source_port,
            destination_port=suricata_meta.destination_port
        )
        
        # Merge protocol-specific fields, preferring non-None values
        for field in [
            'http_method', 'http_uri', 'http_user_agent', 'http_status_code',
            'dns_query', 'dns_query_type', 'dns_response_code', 'dns_answers',
            'tls_sni', 'tls_ja3_fingerprint', 'tls_ja3s_fingerprint', 'tls_version',
            'tcp_flags', 'tcp_window_size', 'tcp_sequence_number',
            'payload_size', 'raw_payload'
        ]:
            suricata_value = getattr(suricata_meta, field)
            zeek_value = getattr(zeek_meta, field)
            
            # Prefer non-None values, with Suricata taking precedence for conflicts
            if suricata_value is not None:
                setattr(merged, field, suricata_value)
            elif zeek_value is not None:
                setattr(merged, field, zeek_value)
        
        return merged