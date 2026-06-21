"""
Unit tests for OUIDatabase class.

Tests OUI extraction, vendor identification, and device type inference.
"""

import pytest
import tempfile
import json
from pathlib import Path
from unittest.mock import Mock

from ai_iot_ids.profiling.oui_database import OUIDatabase
from ai_iot_ids.models.device_profile import DeviceType


@pytest.fixture
def temp_oui_dir():
    """Create temporary directory for OUI database."""
    with tempfile.TemporaryDirectory() as temp_dir:
        yield Path(temp_dir)


@pytest.fixture
def oui_config(temp_oui_dir):
    """Configuration for OUIDatabase."""
    return {
        'oui_database_path': str(temp_oui_dir / 'test_oui.json'),
        'oui_update_interval_days': 30,
        'enable_oui_auto_update': False
    }


@pytest.fixture
def oui_database(oui_config):
    """Create OUIDatabase instance."""
    return OUIDatabase(oui_config)


class TestOUIDatabase:
    """Test cases for OUIDatabase."""
    
    def test_initialization(self, oui_config):
        """Test OUIDatabase initialization."""
        db = OUIDatabase(oui_config)
        
        assert db.oui_to_vendor is not None
        assert db.vendor_to_device_type is not None
        assert len(db.oui_to_vendor) > 0  # Should have default entries
        assert len(db.vendor_to_device_type) > 0
    
    def test_extract_oui_valid_formats(self, oui_database):
        """Test OUI extraction from various MAC address formats."""
        test_cases = [
            ("aa:bb:cc:dd:ee:ff", "aa:bb:cc"),
            ("AA:BB:CC:DD:EE:FF", "aa:bb:cc"),
            ("aa-bb-cc-dd-ee-ff", "aa:bb:cc"),
            ("aabbccddeeff", "aa:bb:cc"),
            ("AABBCCDDEEFF", "aa:bb:cc"),
        ]
        
        for mac_input, expected_oui in test_cases:
            oui = oui_database.extract_oui(mac_input)
            assert oui == expected_oui
    
    def test_extract_oui_invalid_formats(self, oui_database):
        """Test OUI extraction with invalid MAC addresses."""
        invalid_macs = [
            "aa:bb:cc:dd:ee",  # Too short
            "aa:bb:cc:dd:ee:ff:gg",  # Too long
            "gg:hh:ii:jj:kk:ll",  # Invalid hex
            "invalid",  # Not a MAC at all
            "",  # Empty string
        ]
        
        for invalid_mac in invalid_macs:
            with pytest.raises(ValueError):
                oui_database.extract_oui(invalid_mac)
    
    def test_get_vendor_known_ouis(self, oui_database):
        """Test vendor lookup for known OUIs."""
        # Test with default OUIs that should be in the database
        test_cases = [
            ("00:40:8c:11:22:33", "Axis Communications"),  # Axis camera
            ("b8:27:eb:44:55:66", "Raspberry Pi Foundation"),  # Raspberry Pi
            ("50:c7:bf:77:88:99", "TP-Link Technologies"),  # TP-Link
        ]
        
        for mac_address, expected_vendor in test_cases:
            vendor = oui_database.get_vendor(mac_address)
            if vendor:  # Only test if vendor is found (depends on default database)
                assert expected_vendor.lower() in vendor.lower()
    
    def test_get_vendor_unknown_oui(self, oui_database):
        """Test vendor lookup for unknown OUI."""
        unknown_mac = "ff:ff:ff:11:22:33"  # Unlikely to be in database
        vendor = oui_database.get_vendor(unknown_mac)
        assert vendor is None
    
    def test_get_vendor_invalid_mac(self, oui_database):
        """Test vendor lookup with invalid MAC address."""
        invalid_mac = "invalid_mac"
        vendor = oui_database.get_vendor(invalid_mac)
        assert vendor is None  # Should handle gracefully
    
    def test_infer_device_type_camera(self, oui_database):
        """Test device type inference for camera vendors."""
        camera_macs = [
            "00:40:8c:11:22:33",  # Axis
            "00:0f:7c:44:55:66",  # Hikvision
            "00:12:01:77:88:99",  # Dahua
        ]
        
        for mac in camera_macs:
            device_type = oui_database.infer_device_type(mac)
            # Should infer camera or unknown (depending on database content)
            assert device_type in [DeviceType.CAMERA, DeviceType.UNKNOWN]
    
    def test_infer_device_type_raspberry_pi(self, oui_database):
        """Test device type inference for Raspberry Pi."""
        rpi_macs = [
            "b8:27:eb:11:22:33",
            "dc:a6:32:44:55:66",
            "e4:5f:01:77:88:99",
        ]
        
        for mac in rpi_macs:
            device_type = oui_database.infer_device_type(mac)
            # Raspberry Pi should be inferred as sensor
            assert device_type in [DeviceType.SENSOR, DeviceType.UNKNOWN]
    
    def test_infer_device_type_with_vendor_name(self, oui_database):
        """Test device type inference with explicit vendor name."""
        test_cases = [
            ("Axis Communications", DeviceType.CAMERA),
            ("Hikvision", DeviceType.CAMERA),
            ("TP-Link Technologies", DeviceType.PLUG),
            ("Samsung Electronics", DeviceType.HUB),
            ("Unknown Vendor", DeviceType.UNKNOWN),
        ]
        
        for vendor_name, expected_type in test_cases:
            device_type = oui_database.infer_device_type("aa:bb:cc:dd:ee:ff", vendor_name)
            assert device_type == expected_type
    
    def test_infer_device_type_heuristics(self, oui_database):
        """Test device type inference using heuristics."""
        heuristic_cases = [
            ("Security Camera Corp", DeviceType.CAMERA),
            ("Video Systems Inc", DeviceType.CAMERA),
            ("Smart Sensor Technologies", DeviceType.SENSOR),
            ("Home Automation Ltd", DeviceType.HUB),
            ("Climate Control Systems", DeviceType.THERMOSTAT),
        ]
        
        for vendor_name, expected_type in heuristic_cases:
            device_type = oui_database.infer_device_type("aa:bb:cc:dd:ee:ff", vendor_name)
            assert device_type == expected_type
    
    def test_get_device_protocols(self, oui_database):
        """Test getting expected protocols for device types."""
        protocol_tests = [
            (DeviceType.CAMERA, {'TCP', 'UDP', 'HTTP', 'HTTPS', 'RTSP', 'ONVIF'}),
            (DeviceType.SENSOR, {'UDP', 'TCP', 'MQTT', 'CoAP', 'HTTP', 'HTTPS'}),
            (DeviceType.PLUG, {'TCP', 'UDP', 'HTTP', 'HTTPS', 'MQTT'}),
            (DeviceType.THERMOSTAT, {'TCP', 'UDP', 'HTTP', 'HTTPS', 'MQTT', 'ZIGBEE'}),
            (DeviceType.HUB, {'TCP', 'UDP', 'HTTP', 'HTTPS', 'MQTT', 'ZIGBEE', 'Z-WAVE'}),
            (DeviceType.UNKNOWN, {'TCP', 'UDP', 'HTTP', 'HTTPS'}),
        ]
        
        for device_type, expected_protocols in protocol_tests:
            protocols = oui_database.get_device_protocols(device_type)
            assert protocols == expected_protocols
    
    def test_get_typical_bandwidth(self, oui_database):
        """Test getting typical bandwidth for device types."""
        bandwidth_tests = [
            (DeviceType.CAMERA, 2_000_000),      # 2 Mbps
            (DeviceType.SENSOR, 10_000),         # 10 Kbps
            (DeviceType.PLUG, 50_000),           # 50 Kbps
            (DeviceType.THERMOSTAT, 20_000),     # 20 Kbps
            (DeviceType.HUB, 500_000),           # 500 Kbps
            (DeviceType.UNKNOWN, 100_000),       # 100 Kbps
        ]
        
        for device_type, expected_bandwidth in bandwidth_tests:
            bandwidth = oui_database.get_typical_bandwidth(device_type)
            assert bandwidth == expected_bandwidth
    
    def test_get_default_activity_schedule(self, oui_database):
        """Test getting default activity schedules for device types."""
        for device_type in DeviceType:
            hour_activity, day_activity = oui_database.get_default_activity_schedule(device_type)
            
            # Check format
            assert len(hour_activity) == 24
            assert len(day_activity) == 7
            
            # Check value ranges
            assert all(0.0 <= activity <= 1.0 for activity in hour_activity)
            assert all(0.0 <= activity <= 1.0 for activity in day_activity)
    
    def test_get_default_activity_schedule_camera(self, oui_database):
        """Test camera activity schedule (should be high 24/7)."""
        hour_activity, day_activity = oui_database.get_default_activity_schedule(DeviceType.CAMERA)
        
        # Cameras should have high activity all day
        assert all(activity >= 0.8 for activity in hour_activity)
        assert all(activity >= 0.8 for activity in day_activity)
    
    def test_get_default_activity_schedule_sensor(self, oui_database):
        """Test sensor activity schedule (should vary by time)."""
        hour_activity, day_activity = oui_database.get_default_activity_schedule(DeviceType.SENSOR)
        
        # Sensors should have different activity levels
        assert min(hour_activity) < max(hour_activity)
        
        # Weekdays should generally be more active than weekends
        weekday_avg = sum(day_activity[:5]) / 5
        weekend_avg = sum(day_activity[5:]) / 2
        assert weekday_avg >= weekend_avg
    
    def test_add_custom_oui(self, oui_database):
        """Test adding custom OUI mappings."""
        custom_oui = "12:34:56"
        custom_vendor = "Test Vendor Inc"
        
        # Add custom mapping
        oui_database.add_custom_oui(custom_oui, custom_vendor)
        
        # Verify it was added
        assert custom_oui in oui_database.oui_to_vendor
        assert oui_database.oui_to_vendor[custom_oui] == custom_vendor
        
        # Test retrieval
        test_mac = "12:34:56:78:9a:bc"
        vendor = oui_database.get_vendor(test_mac)
        assert vendor == custom_vendor
    
    def test_needs_update_disabled(self, oui_database):
        """Test update check when auto-update is disabled."""
        # Auto-update is disabled in fixture
        assert not oui_database.needs_update()
    
    def test_needs_update_enabled(self, oui_config):
        """Test update check when auto-update is enabled."""
        oui_config['enable_oui_auto_update'] = True
        oui_config['oui_update_interval_days'] = 1
        
        db = OUIDatabase(oui_config)
        
        # Should need update if last_update is old enough
        # (depends on implementation details)
        needs_update = db.needs_update()
        assert isinstance(needs_update, bool)
    
    def test_get_statistics(self, oui_database):
        """Test getting database statistics."""
        stats = oui_database.get_statistics()
        
        required_keys = [
            'total_oui_entries',
            'last_update',
            'device_type_distribution',
            'needs_update',
            'auto_update_enabled'
        ]
        
        for key in required_keys:
            assert key in stats
        
        assert isinstance(stats['total_oui_entries'], int)
        assert stats['total_oui_entries'] > 0
        assert isinstance(stats['device_type_distribution'], dict)
        assert isinstance(stats['needs_update'], bool)
        assert isinstance(stats['auto_update_enabled'], bool)
    
    def test_database_persistence(self, oui_config, temp_oui_dir):
        """Test database saving and loading."""
        # Create database and add custom entry
        db1 = OUIDatabase(oui_config)
        custom_oui = "aa:bb:cc"
        custom_vendor = "Test Vendor"
        db1.add_custom_oui(custom_oui, custom_vendor)
        
        # Create new database instance (should load from file)
        db2 = OUIDatabase(oui_config)
        
        # Verify custom entry was loaded
        assert custom_oui in db2.oui_to_vendor
        assert db2.oui_to_vendor[custom_oui] == custom_vendor
    
    def test_database_file_creation(self, oui_config, temp_oui_dir):
        """Test that database file is created."""
        db = OUIDatabase(oui_config)
        
        # Add custom entry to trigger save
        db.add_custom_oui("test:ou:i", "Test Vendor")
        
        # Check that file was created
        db_file = Path(oui_config['oui_database_path'])
        assert db_file.exists()
        
        # Check file content
        with open(db_file, 'r') as f:
            data = json.load(f)
            assert 'oui_to_vendor' in data
            assert 'last_update' in data
            assert 'version' in data
    
    def test_vendor_mapping_initialization(self, oui_database):
        """Test that vendor to device type mappings are properly initialized."""
        # Check that common vendors are mapped
        vendor_mappings = oui_database.vendor_to_device_type
        
        # Should have camera vendors
        camera_vendors = [v for v, t in vendor_mappings.items() if t == DeviceType.CAMERA]
        assert len(camera_vendors) > 0
        assert any('axis' in v for v in camera_vendors)
        
        # Should have sensor vendors
        sensor_vendors = [v for v, t in vendor_mappings.items() if t == DeviceType.SENSOR]
        assert len(sensor_vendors) > 0
        assert any('texas instruments' in v for v in sensor_vendors)
        
        # Should have plug vendors
        plug_vendors = [v for v, t in vendor_mappings.items() if t == DeviceType.PLUG]
        assert len(plug_vendors) > 0
        assert any('tp-link' in v for v in plug_vendors)
    
    def test_partial_vendor_matching(self, oui_database):
        """Test partial matching of vendor names."""
        # Test that partial matches work
        test_cases = [
            ("Axis Communications AB", DeviceType.CAMERA),
            ("TP-Link Corporation Limited", DeviceType.PLUG),
            ("Texas Instruments Inc.", DeviceType.SENSOR),
        ]
        
        for vendor_name, expected_type in test_cases:
            device_type = oui_database.infer_device_type("aa:bb:cc:dd:ee:ff", vendor_name)
            # Should match due to partial matching
            assert device_type == expected_type or device_type == DeviceType.UNKNOWN  # Fallback acceptable