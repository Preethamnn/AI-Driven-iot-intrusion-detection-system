"""
OUI (Organizationally Unique Identifier) Database for device vendor identification.

This module provides functionality to identify device vendors from MAC addresses
using the IEEE OUI database and map them to device types for profiling.
"""

import re
import json
from typing import Dict, Optional, Set, Tuple
from pathlib import Path
from datetime import datetime, timedelta

from ..models.device_profile import DeviceType
from ..utils.logging_config import get_logger


class OUIDatabase:
    """
    OUI database for MAC address vendor identification and device type mapping.
    
    Provides functionality to:
    - Extract OUI from MAC addresses
    - Map OUI to vendor names
    - Infer device types from vendor information
    - Maintain local OUI database with periodic updates
    """
    
    def __init__(self, config: Dict, logger=None):
        """
        Initialize OUI database.
        
        Args:
            config: Configuration dictionary
            logger: Optional logger instance
        """
        self.logger = logger or get_logger(__name__)
        self.config = config
        
        # OUI database configuration
        self.database_path = Path(config.get('oui_database_path', 'data/oui_database.json'))
        self.update_interval_days = config.get('oui_update_interval_days', 30)
        self.enable_auto_update = config.get('enable_oui_auto_update', False)
        
        # In-memory OUI database
        self.oui_to_vendor: Dict[str, str] = {}
        self.vendor_to_device_type: Dict[str, DeviceType] = {}
        self.last_update: Optional[datetime] = None
        
        # Initialize vendor to device type mappings
        self._initialize_vendor_mappings()
        
        # Load OUI database
        self._load_database()
    
    def _initialize_vendor_mappings(self) -> None:
        """Initialize vendor name to device type mappings."""
        # Camera vendors
        camera_vendors = {
            'axis', 'hikvision', 'dahua', 'bosch', 'sony', 'panasonic',
            'vivotek', 'geovision', 'avigilon', 'hanwha', 'flir',
            'mobotix', 'acti', 'arecont', 'pelco', 'honeywell'
        }
        
        # Smart plug/switch vendors
        plug_vendors = {
            'tp-link', 'belkin', 'wemo', 'kasa', 'amazon', 'wyze',
            'gosund', 'treatlife', 'meross', 'teckin', 'smart life'
        }
        
        # Thermostat vendors
        thermostat_vendors = {
            'nest', 'ecobee', 'honeywell', 'emerson', 'johnson controls',
            'carrier', 'trane', 'lennox', 'white-rodgers', 'lux'
        }
        
        # Sensor vendors (including IoT sensors)
        sensor_vendors = {
            'texas instruments', 'nordic semiconductor', 'silicon labs',
            'espressif', 'particle', 'arduino', 'raspberry pi foundation',
            'adafruit', 'sparkfun', 'seeed', 'mikroe', 'digi'
        }
        
        # Hub/gateway vendors
        hub_vendors = {
            'samsung', 'philips', 'hubitat', 'smartthings', 'wink',
            'vera', 'fibaro', 'aeotec', 'z-wave', 'zigbee'
        }
        
        # Build vendor to device type mapping
        for vendor in camera_vendors:
            self.vendor_to_device_type[vendor.lower()] = DeviceType.CAMERA
        
        for vendor in plug_vendors:
            self.vendor_to_device_type[vendor.lower()] = DeviceType.PLUG
        
        for vendor in thermostat_vendors:
            self.vendor_to_device_type[vendor.lower()] = DeviceType.THERMOSTAT
        
        for vendor in sensor_vendors:
            self.vendor_to_device_type[vendor.lower()] = DeviceType.SENSOR
        
        for vendor in hub_vendors:
            self.vendor_to_device_type[vendor.lower()] = DeviceType.HUB
    
    def _load_database(self) -> None:
        """Load OUI database from file or create default database."""
        try:
            if self.database_path.exists():
                with open(self.database_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self.oui_to_vendor = data.get('oui_to_vendor', {})
                    self.last_update = datetime.fromisoformat(data.get('last_update', '2024-01-01T00:00:00'))
                    self.logger.info(f"Loaded OUI database with {len(self.oui_to_vendor)} entries")
            else:
                self._create_default_database()
                self.logger.info("Created default OUI database")
        except Exception as e:
            self.logger.error(f"Failed to load OUI database: {e}")
            self._create_default_database()
    
    def _create_default_database(self) -> None:
        """Create a default OUI database with common vendors."""
        # Common OUI prefixes for known IoT device vendors
        default_ouis = {
            # Camera vendors
            '00:40:8c': 'Axis Communications',
            '00:0f:7c': 'Hikvision',
            '00:12:01': 'Dahua Technology',
            '00:0c:e5': 'Sony Corporation',
            '00:80:f0': 'Panasonic',
            '00:02:d1': 'Vivotek Inc.',
            
            # Network equipment (common in IoT deployments)
            '00:50:56': 'VMware',
            '08:00:27': 'Oracle VirtualBox',
            '00:1b:21': 'Intel Corporate',
            '00:15:5d': 'Microsoft Corporation',
            
            # Smart home vendors
            '50:c7:bf': 'TP-Link Technologies',
            'ec:fa:bc': 'Belkin International',
            '44:61:32': 'Amazon Technologies',
            '2c:aa:8e': 'Wyze Labs',
            
            # Raspberry Pi Foundation
            'b8:27:eb': 'Raspberry Pi Foundation',
            'dc:a6:32': 'Raspberry Pi Foundation',
            'e4:5f:01': 'Raspberry Pi Foundation',
            
            # Arduino and maker boards
            '00:1e:c0': 'Arduino',
            '98:84:e3': 'Espressif Inc.',
            '24:0a:c4': 'Espressif Inc.',
            '30:ae:a4': 'Espressif Inc.',
            
            # Samsung (SmartThings and other IoT)
            '00:16:6c': 'Samsung Electronics',
            '28:6d:cd': 'Samsung Electronics',
            'd8:50:e6': 'Samsung Electronics',
            
            # Apple (HomeKit devices)
            '00:03:93': 'Apple Inc.',
            '00:17:f2': 'Apple Inc.',
            '28:cf:e9': 'Apple Inc.',
            
            # Google (Nest devices)
            '18:b4:30': 'Google Inc.',
            '64:16:66': 'Google Inc.',
            'f4:f5:d8': 'Google Inc.',
        }
        
        self.oui_to_vendor = default_ouis
        self.last_update = datetime.utcnow()
        self._save_database()
    
    def _save_database(self) -> None:
        """Save OUI database to file."""
        try:
            self.database_path.parent.mkdir(parents=True, exist_ok=True)
            data = {
                'oui_to_vendor': self.oui_to_vendor,
                'last_update': self.last_update.isoformat() if self.last_update else datetime.utcnow().isoformat(),
                'version': '1.0'
            }
            with open(self.database_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            self.logger.debug(f"Saved OUI database to {self.database_path}")
        except Exception as e:
            self.logger.error(f"Failed to save OUI database: {e}")
    
    def extract_oui(self, mac_address: str) -> str:
        """
        Extract OUI (first 3 octets) from MAC address.
        
        Args:
            mac_address: MAC address in various formats
            
        Returns:
            OUI in lowercase format (xx:xx:xx)
            
        Raises:
            ValueError: If MAC address format is invalid
        """
        if not mac_address or not isinstance(mac_address, str):
            raise ValueError(f"Invalid MAC address: {mac_address}")
        
        # First check for invalid hex characters before cleaning
        # Remove only separators (: - .) but keep all alphanumeric
        mac_no_separators = re.sub(r'[:\-\.]', '', mac_address)
        
        # Check if all remaining characters are valid hex
        if not re.match(r'^[0-9a-fA-F]+$', mac_no_separators):
            raise ValueError(f"Invalid MAC address format: {mac_address} (contains non-hex characters)")
        
        # Now clean and normalize
        mac_clean = mac_no_separators.upper()
        
        # Validate length
        if len(mac_clean) != 12:
            raise ValueError(f"Invalid MAC address length: {mac_address} (expected 12 hex characters, got {len(mac_clean)})")
        
        # Extract first 6 characters (3 octets) and format as OUI
        oui_hex = mac_clean[:6]
        oui = ':'.join([oui_hex[i:i+2] for i in range(0, 6, 2)]).lower()
        
        return oui
    
    def get_vendor(self, mac_address: str) -> Optional[str]:
        """
        Get vendor name from MAC address.
        
        Args:
            mac_address: Device MAC address
            
        Returns:
            Vendor name if found, None otherwise
        """
        try:
            oui = self.extract_oui(mac_address)
            return self.oui_to_vendor.get(oui)
        except ValueError as e:
            self.logger.warning(f"Invalid MAC address format: {mac_address} - {e}")
            return None
    
    def infer_device_type(self, mac_address: str, vendor_name: Optional[str] = None) -> DeviceType:
        """
        Infer device type from MAC address and vendor information.
        
        Args:
            mac_address: Device MAC address
            vendor_name: Optional vendor name (if already known)
            
        Returns:
            Inferred device type
        """
        if vendor_name is None:
            vendor_name = self.get_vendor(mac_address)
        
        if vendor_name is None:
            return DeviceType.UNKNOWN
        
        # Check direct vendor mapping
        vendor_lower = vendor_name.lower()
        if vendor_lower in self.vendor_to_device_type:
            return self.vendor_to_device_type[vendor_lower]
        
        # Check partial matches for vendor names
        for known_vendor, device_type in self.vendor_to_device_type.items():
            if known_vendor in vendor_lower or vendor_lower in known_vendor:
                return device_type
        
        # Heuristic-based inference from vendor name
        vendor_lower = vendor_name.lower()
        
        # Camera keywords
        if any(keyword in vendor_lower for keyword in ['camera', 'vision', 'video', 'surveillance', 'security']):
            return DeviceType.CAMERA
        
        # Sensor keywords
        if any(keyword in vendor_lower for keyword in ['sensor', 'instruments', 'semiconductor', 'arduino', 'raspberry']):
            return DeviceType.SENSOR
        
        # Smart home keywords
        if any(keyword in vendor_lower for keyword in ['smart', 'home', 'automation', 'iot']):
            return DeviceType.HUB
        
        # Thermostat keywords
        if any(keyword in vendor_lower for keyword in ['thermostat', 'climate', 'hvac', 'temperature']):
            return DeviceType.THERMOSTAT
        
        # Default to unknown
        return DeviceType.UNKNOWN
    
    def get_device_protocols(self, device_type: DeviceType) -> Set[str]:
        """
        Get expected protocols for a device type.
        
        Args:
            device_type: Type of device
            
        Returns:
            Set of expected protocol names
        """
        protocol_mappings = {
            DeviceType.CAMERA: {'TCP', 'UDP', 'HTTP', 'HTTPS', 'RTSP', 'ONVIF'},
            DeviceType.SENSOR: {'UDP', 'TCP', 'MQTT', 'CoAP', 'HTTP', 'HTTPS'},
            DeviceType.PLUG: {'TCP', 'UDP', 'HTTP', 'HTTPS', 'MQTT'},
            DeviceType.THERMOSTAT: {'TCP', 'UDP', 'HTTP', 'HTTPS', 'MQTT', 'ZIGBEE'},
            DeviceType.HUB: {'TCP', 'UDP', 'HTTP', 'HTTPS', 'MQTT', 'ZIGBEE', 'Z-WAVE'},
            DeviceType.UNKNOWN: {'TCP', 'UDP', 'HTTP', 'HTTPS'}
        }
        
        return protocol_mappings.get(device_type, {'TCP', 'UDP'})
    
    def get_typical_bandwidth(self, device_type: DeviceType) -> int:
        """
        Get typical bandwidth usage for a device type in bits per second.
        
        Args:
            device_type: Type of device
            
        Returns:
            Typical bandwidth in bps
        """
        bandwidth_mappings = {
            DeviceType.CAMERA: 2_000_000,      # 2 Mbps for video streaming
            DeviceType.SENSOR: 10_000,         # 10 Kbps for sensor data
            DeviceType.PLUG: 50_000,           # 50 Kbps for smart plug communication
            DeviceType.THERMOSTAT: 20_000,     # 20 Kbps for thermostat data
            DeviceType.HUB: 500_000,           # 500 Kbps for hub coordination
            DeviceType.UNKNOWN: 100_000        # 100 Kbps default
        }
        
        return bandwidth_mappings.get(device_type, 100_000)
    
    def get_default_activity_schedule(self, device_type: DeviceType) -> Tuple[list, list]:
        """
        Get default activity schedule for a device type.
        
        Args:
            device_type: Type of device
            
        Returns:
            Tuple of (hour_of_day, day_of_week) activity patterns
        """
        if device_type == DeviceType.CAMERA:
            # Cameras are typically active 24/7 with slight variations
            hour_of_day = [0.9] * 24  # High activity all day
            day_of_week = [0.9] * 7   # Active all week
        
        elif device_type == DeviceType.SENSOR:
            # Sensors typically have periodic reporting patterns
            hour_of_day = [0.3] * 6 + [0.7] * 12 + [0.4] * 6  # More active during day
            day_of_week = [0.8] * 5 + [0.5] * 2  # Less active on weekends
        
        elif device_type == DeviceType.PLUG:
            # Smart plugs follow usage patterns
            hour_of_day = [0.2] * 6 + [0.8] * 4 + [0.6] * 8 + [0.9] * 4 + [0.4] * 2
            day_of_week = [0.8] * 5 + [0.6] * 2  # Different weekend patterns
        
        elif device_type == DeviceType.THERMOSTAT:
            # Thermostats are more active during temperature changes
            hour_of_day = [0.4] * 6 + [0.8] * 2 + [0.5] * 8 + [0.8] * 4 + [0.6] * 4
            day_of_week = [0.8] * 5 + [0.7] * 2  # Slightly less active on weekends
        
        elif device_type == DeviceType.HUB:
            # Hubs coordinate other devices, so moderate constant activity
            hour_of_day = [0.6] * 24  # Consistent activity
            day_of_week = [0.7] * 7   # Consistent throughout week
        
        else:  # UNKNOWN
            # Conservative default pattern
            hour_of_day = [0.3] * 6 + [0.6] * 12 + [0.4] * 6
            day_of_week = [0.5] * 7
        
        return hour_of_day, day_of_week
    
    def needs_update(self) -> bool:
        """
        Check if OUI database needs updating.
        
        Returns:
            True if database should be updated
        """
        if not self.enable_auto_update or not self.last_update:
            return False
        
        update_threshold = datetime.utcnow() - timedelta(days=self.update_interval_days)
        return self.last_update < update_threshold
    
    def add_custom_oui(self, oui: str, vendor: str) -> None:
        """
        Add custom OUI mapping to database.
        
        Args:
            oui: OUI in format xx:xx:xx
            vendor: Vendor name
        """
        oui_normalized = oui.lower()
        self.oui_to_vendor[oui_normalized] = vendor
        self.logger.info(f"Added custom OUI mapping: {oui_normalized} -> {vendor}")
        self._save_database()
    
    def get_statistics(self) -> Dict[str, any]:
        """
        Get OUI database statistics.
        
        Returns:
            Dictionary containing database statistics
        """
        vendor_counts = {}
        for vendor in self.oui_to_vendor.values():
            vendor_lower = vendor.lower()
            device_type = DeviceType.UNKNOWN
            
            # Find device type for this vendor
            for known_vendor, dtype in self.vendor_to_device_type.items():
                if known_vendor in vendor_lower or vendor_lower in known_vendor:
                    device_type = dtype
                    break
            
            vendor_counts[device_type.value] = vendor_counts.get(device_type.value, 0) + 1
        
        return {
            'total_oui_entries': len(self.oui_to_vendor),
            'last_update': self.last_update.isoformat() if self.last_update else None,
            'device_type_distribution': vendor_counts,
            'needs_update': self.needs_update(),
            'auto_update_enabled': self.enable_auto_update
        }