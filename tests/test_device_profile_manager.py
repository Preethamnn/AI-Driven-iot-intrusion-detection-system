"""
Unit tests for DeviceProfileManager class.

Tests device profile creation, behavioral baseline establishment,
and anomaly detection functionality.
"""

import pytest
import pytest_asyncio
import asyncio
import tempfile
import json
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import Mock, patch

from ai_iot_ids.profiling.device_profile_manager import DeviceProfileManager
from ai_iot_ids.models.device_profile import DeviceProfile, DeviceType
from ai_iot_ids.models.network_flow import NetworkFlow


@pytest.fixture
def temp_profiles_dir():
    """Create temporary directory for profile storage."""
    with tempfile.TemporaryDirectory() as temp_dir:
        yield Path(temp_dir)


@pytest.fixture
def profile_manager_config(temp_profiles_dir):
    """Configuration for DeviceProfileManager."""
    return {
        'profiles_path': str(temp_profiles_dir),
        'auto_save_interval_minutes': 0,  # Disable auto-save for tests
        'profile_learning_window_days': 7,
        'min_observations_for_baseline': 10,
        'activity_window_minutes': 60,
        'periodicity_analysis_hours': 24,
        'anomaly_threshold': 0.7,
        'oui_database': {
            'oui_database_path': str(temp_profiles_dir / 'test_oui.json'),
            'enable_oui_auto_update': False
        }
    }


@pytest_asyncio.fixture
async def profile_manager(profile_manager_config):
    """Create and initialize DeviceProfileManager."""
    manager = DeviceProfileManager(profile_manager_config)
    await manager.initialize()
    await manager.start()
    yield manager
    await manager.stop()


@pytest.fixture
def sample_network_flows():
    """Create sample network flows for testing."""
    base_time = datetime.utcnow()
    flows = []
    
    for i in range(10):
        flow = NetworkFlow(
            timestamp=base_time + timedelta(minutes=i * 5),
            source_ip="192.168.1.100",
            destination_ip=f"192.168.1.{200 + (i % 3)}",
            source_port=12345 + i,
            destination_port=80 if i % 2 == 0 else 443,
            protocol="TCP",
            bytes_sent=1000 + i * 100,
            bytes_received=500 + i * 50,
            packets_sent=10 + i,
            packets_received=5 + i,
            duration_ms=1000 + i * 100,
            inter_arrival_mean_ms=100.0,
            inter_arrival_std_ms=10.0,
            jitter_ms=5.0,
            tcp_flags=["SYN", "ACK"],
            retransmissions=0,
            syn_fin_ratio=1.0,
            unique_destinations=1,
            fan_out_ratio=0.1,
            fan_in_ratio=0.1,
            port_distribution_entropy=0.5
        )
        flows.append(flow)
    
    return flows


class TestDeviceProfileManager:
    """Test cases for DeviceProfileManager."""
    
    @pytest.mark.asyncio
    async def test_initialization(self, profile_manager_config):
        """Test DeviceProfileManager initialization."""
        manager = DeviceProfileManager(profile_manager_config)
        await manager.initialize()
        
        assert manager.profiles == {}
        assert manager.profiles_created == 0
        assert manager.profiles_updated == 0
        assert manager.oui_database is not None
        
        await manager.stop()
    
    @pytest.mark.asyncio
    async def test_create_device_profile_basic(self, profile_manager):
        """Test basic device profile creation."""
        mac_address = "aa:bb:cc:dd:ee:ff"
        
        profile = await profile_manager.create_device_profile(mac_address)
        
        assert profile.device_id == mac_address.lower()
        assert profile.vendor_oui == "aa:bb:cc"
        assert profile.device_type in DeviceType
        assert profile.confidence_score == 0.1  # Initial low confidence
        assert profile.observation_count == 0
        assert len(profile.normal_protocols) > 0
        assert profile.typical_bandwidth_bps > 0
        assert profile.activity_schedule is not None
        
        # Check that profile is stored
        assert mac_address.lower() in profile_manager.profiles
        assert profile_manager.profiles_created == 1
    
    @pytest.mark.asyncio
    async def test_create_device_profile_with_flows(self, profile_manager, sample_network_flows):
        """Test device profile creation with initial flows."""
        mac_address = "b8:27:eb:12:34:56"  # Raspberry Pi OUI
        
        profile = await profile_manager.create_device_profile(mac_address, sample_network_flows)
        
        assert profile.device_id == mac_address.lower()
        assert profile.observation_count > 0
        assert profile.confidence_score > 0.1  # Should be higher with observations
        assert len(profile.allowed_destinations) > 0
        assert "TCP" in profile.normal_protocols
    
    @pytest.mark.asyncio
    async def test_update_device_profile(self, profile_manager, sample_network_flows):
        """Test updating device profile with new flows."""
        mac_address = "00:40:8c:11:22:33"  # Axis camera OUI
        
        # Create initial profile
        profile = await profile_manager.create_device_profile(mac_address)
        initial_confidence = profile.confidence_score
        
        # Update with flows
        updated_profile = await profile_manager.update_device_profile(mac_address, sample_network_flows)
        
        assert updated_profile.device_id == mac_address.lower()
        assert updated_profile.observation_count > 0
        assert updated_profile.confidence_score > initial_confidence
        assert profile_manager.profiles_updated == 1
    
    @pytest.mark.asyncio
    async def test_protocol_baseline_learning(self, profile_manager):
        """Test protocol baseline learning from flows."""
        mac_address = "00:50:56:aa:bb:cc"
        
        # Create flows with different protocols
        flows = []
        base_time = datetime.utcnow()
        
        for i in range(20):
            protocol = "TCP" if i < 15 else "UDP"  # 75% TCP, 25% UDP
            flow = NetworkFlow(
                timestamp=base_time + timedelta(minutes=i),
                source_ip="192.168.1.100",
                destination_ip="192.168.1.200",
                source_port=12345,
                destination_port=80,
                protocol=protocol,
                bytes_sent=1000,
                bytes_received=500,
                packets_sent=10,
                packets_received=5,
                duration_ms=1000,
                inter_arrival_mean_ms=100.0,
                inter_arrival_std_ms=10.0,
                jitter_ms=5.0,
                tcp_flags=["SYN", "ACK"] if protocol == "TCP" else [],
                retransmissions=0,
                syn_fin_ratio=1.0,
                unique_destinations=1,
                fan_out_ratio=0.1,
                fan_in_ratio=0.1,
                port_distribution_entropy=0.5
            )
            flows.append(flow)
        
        profile = await profile_manager.create_device_profile(mac_address, flows)
        
        # Both TCP and UDP should be in normal protocols (>5% usage)
        assert "TCP" in profile.normal_protocols
        assert "UDP" in profile.normal_protocols
    
    @pytest.mark.asyncio
    async def test_activity_schedule_learning(self, profile_manager):
        """Test activity schedule learning from temporal patterns."""
        mac_address = "ec:fa:bc:11:22:33"
        
        # Create flows with specific time patterns
        flows = []
        base_time = datetime.utcnow().replace(hour=9, minute=0, second=0, microsecond=0)
        
        # Create flows mostly during business hours (9-17)
        for day in range(7):
            for hour in range(24):
                if 9 <= hour <= 17:  # Business hours
                    for _ in range(3):  # More activity during business hours
                        flow_time = base_time + timedelta(days=day, hours=hour, minutes=10)
                        flow = NetworkFlow(
                            timestamp=flow_time,
                            source_ip="192.168.1.100",
                            destination_ip="192.168.1.200",
                            source_port=12345,
                            destination_port=80,
                            protocol="TCP",
                            bytes_sent=1000,
                            bytes_received=500,
                            packets_sent=10,
                            packets_received=5,
                            duration_ms=1000,
                            inter_arrival_mean_ms=100.0,
                            inter_arrival_std_ms=10.0,
                            jitter_ms=5.0,
                            tcp_flags=["SYN", "ACK"],
                            retransmissions=0,
                            syn_fin_ratio=1.0,
                            unique_destinations=1,
                            fan_out_ratio=0.1,
                            fan_in_ratio=0.1,
                            port_distribution_entropy=0.5
                        )
                        flows.append(flow)
                elif hour in [8, 18]:  # Some activity at edges
                    flow_time = base_time + timedelta(days=day, hours=hour, minutes=30)
                    flow = NetworkFlow(
                        timestamp=flow_time,
                        source_ip="192.168.1.100",
                        destination_ip="192.168.1.200",
                        source_port=12345,
                        destination_port=80,
                        protocol="TCP",
                        bytes_sent=500,
                        bytes_received=250,
                        packets_sent=5,
                        packets_received=3,
                        duration_ms=500,
                        inter_arrival_mean_ms=100.0,
                        inter_arrival_std_ms=10.0,
                        jitter_ms=5.0,
                        tcp_flags=["SYN", "ACK"],
                        retransmissions=0,
                        syn_fin_ratio=1.0,
                        unique_destinations=1,
                        fan_out_ratio=0.1,
                        fan_in_ratio=0.1,
                        port_distribution_entropy=0.5
                    )
                    flows.append(flow)
        
        profile = await profile_manager.create_device_profile(mac_address, flows)
        
        assert profile.activity_schedule is not None
        
        # Business hours should have higher activity
        business_hours_activity = [profile.activity_schedule.hour_of_day[h] for h in range(9, 18)]
        night_hours_activity = [profile.activity_schedule.hour_of_day[h] for h in range(0, 6)]
        
        avg_business = sum(business_hours_activity) / len(business_hours_activity)
        avg_night = sum(night_hours_activity) / len(night_hours_activity)
        
        assert avg_business > avg_night
    
    @pytest.mark.asyncio
    async def test_bandwidth_baseline_learning(self, profile_manager):
        """Test bandwidth baseline learning."""
        mac_address = "00:1b:21:aa:bb:cc"
        
        # Create flows with consistent bandwidth pattern
        flows = []
        base_time = datetime.utcnow()
        
        for i in range(50):
            # Simulate consistent 1 Mbps traffic
            bytes_sent = 125000  # 1 Mbps for 1 second
            duration_ms = 1000
            
            flow = NetworkFlow(
                timestamp=base_time + timedelta(seconds=i * 2),
                source_ip="192.168.1.100",
                destination_ip="192.168.1.200",
                source_port=12345,
                destination_port=80,
                protocol="TCP",
                bytes_sent=bytes_sent,
                bytes_received=bytes_sent // 2,
                packets_sent=100,
                packets_received=50,
                duration_ms=duration_ms,
                inter_arrival_mean_ms=100.0,
                inter_arrival_std_ms=10.0,
                jitter_ms=5.0,
                tcp_flags=["SYN", "ACK"],
                retransmissions=0,
                syn_fin_ratio=1.0,
                unique_destinations=1,
                fan_out_ratio=0.1,
                fan_in_ratio=0.1,
                port_distribution_entropy=0.5
            )
            flows.append(flow)
        
        profile = await profile_manager.create_device_profile(mac_address, flows)
        
        # Should learn approximately 1.5 Mbps baseline (bytes_sent + bytes_received)
        # 125,000 bytes sent + 62,500 bytes received = 187,500 bytes/sec = 1.5 Mbps
        expected_bps = 1_500_000  # 1.5 Mbps
        tolerance = 0.3  # 30% tolerance (to account for smoothing and median calculation)
        
        assert abs(profile.typical_bandwidth_bps - expected_bps) / expected_bps < tolerance
    
    @pytest.mark.asyncio
    async def test_periodicity_analysis(self, profile_manager, sample_network_flows):
        """Test periodicity analysis functionality."""
        mac_address = "28:6d:cd:11:22:33"
        
        # Create profile with flows
        await profile_manager.create_device_profile(mac_address, sample_network_flows)
        
        # Analyze periodicity
        periodicity = await profile_manager.analyze_periodicity(mac_address, hours_back=24)
        
        assert 'mean_interval_seconds' in periodicity
        assert 'periodicity_score' in periodicity
        assert 'observation_count' in periodicity
        assert periodicity['observation_count'] > 0
    
    @pytest.mark.asyncio
    async def test_anomaly_detection_protocol(self, profile_manager, sample_network_flows):
        """Test protocol anomaly detection."""
        mac_address = "00:03:93:11:22:33"
        
        # Create profile with TCP flows
        tcp_flows = [f for f in sample_network_flows if f.protocol == "TCP"]
        profile = await profile_manager.create_device_profile(mac_address, tcp_flows)
        
        # Make profile mature for anomaly detection
        profile.observation_count = 200
        profile.confidence_score = 0.8
        # Update the profile in the manager's dict
        profile_manager.profiles[mac_address.lower()] = profile
        
        # Create anomalous UDP flow
        anomalous_flow = NetworkFlow(
            timestamp=datetime.utcnow(),
            source_ip="192.168.1.100",
            destination_ip="192.168.1.200",
            source_port=12345,
            destination_port=53,
            protocol="UDP",  # Anomalous protocol
            bytes_sent=1000,
            bytes_received=500,
            packets_sent=10,
            packets_received=5,
            duration_ms=1000,
            inter_arrival_mean_ms=100.0,
            inter_arrival_std_ms=10.0,
            jitter_ms=5.0,
            tcp_flags=[],
            retransmissions=0,
            syn_fin_ratio=0.0,
            unique_destinations=1,
            fan_out_ratio=0.1,
            fan_in_ratio=0.1,
            port_distribution_entropy=0.5
        )
        
        anomalies = await profile_manager.detect_anomalies(mac_address, [anomalous_flow])
        
        assert len(anomalies) > 0
        protocol_anomalies = [a for a in anomalies if a['type'] == 'protocol_anomaly']
        assert len(protocol_anomalies) > 0
        assert protocol_anomalies[0]['details']['observed_protocol'] == 'UDP'
    
    @pytest.mark.asyncio
    async def test_anomaly_detection_destination(self, profile_manager, sample_network_flows):
        """Test destination anomaly detection."""
        mac_address = "d8:50:e6:11:22:33"
        
        # Create profile with specific destinations
        profile = await profile_manager.create_device_profile(mac_address, sample_network_flows)
        
        # Make profile mature
        profile.observation_count = 200
        profile.confidence_score = 0.8
        
        # Create flow to unauthorized destination
        anomalous_flow = NetworkFlow(
            timestamp=datetime.utcnow(),
            source_ip="192.168.1.100",
            destination_ip="10.0.0.1",  # Different network
            source_port=12345,
            destination_port=80,
            protocol="TCP",
            bytes_sent=1000,
            bytes_received=500,
            packets_sent=10,
            packets_received=5,
            duration_ms=1000,
            inter_arrival_mean_ms=100.0,
            inter_arrival_std_ms=10.0,
            jitter_ms=5.0,
            tcp_flags=["SYN", "ACK"],
            retransmissions=0,
            syn_fin_ratio=1.0,
            unique_destinations=1,
            fan_out_ratio=0.1,
            fan_in_ratio=0.1,
            port_distribution_entropy=0.5
        )
        
        anomalies = await profile_manager.detect_anomalies(mac_address, [anomalous_flow])
        
        destination_anomalies = [a for a in anomalies if a['type'] == 'destination_anomaly']
        assert len(destination_anomalies) > 0
        assert destination_anomalies[0]['details']['destination_ip'] == '10.0.0.1'
    
    @pytest.mark.asyncio
    async def test_anomaly_detection_bandwidth(self, profile_manager):
        """Test bandwidth anomaly detection."""
        mac_address = "18:b4:30:11:22:33"
        
        # Create profile with normal bandwidth flows
        normal_flows = []
        base_time = datetime.utcnow()
        
        for i in range(20):
            flow = NetworkFlow(
                timestamp=base_time + timedelta(minutes=i),
                source_ip="192.168.1.100",
                destination_ip="192.168.1.200",
                source_port=12345,
                destination_port=80,
                protocol="TCP",
                bytes_sent=1000,  # Normal bandwidth
                bytes_received=500,
                packets_sent=10,
                packets_received=5,
                duration_ms=1000,
                inter_arrival_mean_ms=100.0,
                inter_arrival_std_ms=10.0,
                jitter_ms=5.0,
                tcp_flags=["SYN", "ACK"],
                retransmissions=0,
                syn_fin_ratio=1.0,
                unique_destinations=1,
                fan_out_ratio=0.1,
                fan_in_ratio=0.1,
                port_distribution_entropy=0.5
            )
            normal_flows.append(flow)
        
        profile = await profile_manager.create_device_profile(mac_address, normal_flows)
        
        # Make profile mature
        profile.observation_count = 200
        profile.confidence_score = 0.8
        
        # Create high bandwidth flow
        high_bandwidth_flow = NetworkFlow(
            timestamp=datetime.utcnow(),
            source_ip="192.168.1.100",
            destination_ip="192.168.1.200",
            source_port=12345,
            destination_port=80,
            protocol="TCP",
            bytes_sent=100000,  # 10x normal bandwidth
            bytes_received=50000,
            packets_sent=1000,
            packets_received=500,
            duration_ms=1000,
            inter_arrival_mean_ms=100.0,
            inter_arrival_std_ms=10.0,
            jitter_ms=5.0,
            tcp_flags=["SYN", "ACK"],
            retransmissions=0,
            syn_fin_ratio=1.0,
            unique_destinations=1,
            fan_out_ratio=0.1,
            fan_in_ratio=0.1,
            port_distribution_entropy=0.5
        )
        
        anomalies = await profile_manager.detect_anomalies(mac_address, [high_bandwidth_flow])
        
        bandwidth_anomalies = [a for a in anomalies if a['type'] == 'bandwidth_anomaly']
        assert len(bandwidth_anomalies) > 0
        assert bandwidth_anomalies[0]['details']['ratio'] > 5.0
    
    @pytest.mark.asyncio
    async def test_profile_persistence(self, profile_manager, sample_network_flows, temp_profiles_dir):
        """Test profile saving and loading."""
        mac_address = "f4:f5:d8:11:22:33"
        
        # Create profile
        profile = await profile_manager.create_device_profile(mac_address, sample_network_flows)
        original_confidence = profile.confidence_score
        
        # Save profiles
        await profile_manager._save_profiles()
        
        # Check that profile file exists (with sanitized filename)
        safe_filename = mac_address.lower().replace(':', '-')
        profile_file = temp_profiles_dir / f"{safe_filename}.json"
        assert profile_file.exists()
        
        # Create new manager and load profiles
        new_manager = DeviceProfileManager(profile_manager.config)
        await new_manager.initialize()
        
        # Check that profile was loaded
        loaded_profile = await new_manager.get_device_profile(mac_address)
        assert loaded_profile is not None
        assert loaded_profile.device_id == mac_address.lower()
        assert loaded_profile.confidence_score == original_confidence
        
        await new_manager.stop()
    
    @pytest.mark.asyncio
    async def test_list_and_delete_profiles(self, profile_manager, sample_network_flows):
        """Test listing and deleting profiles."""
        # Create multiple profiles
        mac_addresses = ["aa:bb:cc:11:11:11", "bb:cc:dd:22:22:22", "cc:dd:ee:33:33:33"]
        
        for mac in mac_addresses:
            await profile_manager.create_device_profile(mac, sample_network_flows[:3])
        
        # List all profiles
        all_profiles = await profile_manager.list_device_profiles()
        assert len(all_profiles) == 3
        
        # Delete one profile
        deleted = await profile_manager.delete_device_profile(mac_addresses[0])
        assert deleted is True
        
        # Check that profile was removed
        remaining_profiles = await profile_manager.list_device_profiles()
        assert len(remaining_profiles) == 2
        
        # Try to delete non-existent profile
        deleted = await profile_manager.delete_device_profile("ff:ff:ff:ff:ff:ff")
        assert deleted is False
    
    @pytest.mark.asyncio
    async def test_statistics(self, profile_manager, sample_network_flows):
        """Test statistics collection."""
        # Create profiles of different types
        camera_mac = "00:40:8c:11:22:33"  # Axis camera
        sensor_mac = "b8:27:eb:44:55:66"  # Raspberry Pi
        
        await profile_manager.create_device_profile(camera_mac, sample_network_flows[:5])
        await profile_manager.create_device_profile(sensor_mac, sample_network_flows[5:])
        
        # Get statistics
        stats = await profile_manager.get_statistics()
        
        assert stats['total_profiles'] == 2
        assert stats['profiles_created'] == 2
        assert 'device_type_distribution' in stats
        assert 'average_confidence_score' in stats
        assert 'oui_database_stats' in stats
        assert stats['total_observations'] > 0
    
    @pytest.mark.asyncio
    async def test_invalid_mac_address(self, profile_manager):
        """Test handling of invalid MAC addresses."""
        invalid_macs = ["invalid", "aa:bb:cc:dd", "gg:hh:ii:jj:kk:ll"]
        
        for invalid_mac in invalid_macs:
            with pytest.raises(Exception):  # Should raise ValueError or IDSError
                await profile_manager.create_device_profile(invalid_mac)
    
    @pytest.mark.asyncio
    async def test_immature_profile_no_anomalies(self, profile_manager, sample_network_flows):
        """Test that immature profiles don't generate anomalies."""
        mac_address = "64:16:66:11:22:33"
        
        # Create profile with low confidence
        profile = await profile_manager.create_device_profile(mac_address, sample_network_flows[:2])
        
        # Ensure profile is not mature
        assert not profile.is_mature_profile()
        
        # Try to detect anomalies
        anomalies = await profile_manager.detect_anomalies(mac_address, sample_network_flows[2:4])
        
        # Should return empty list for immature profile
        assert len(anomalies) == 0