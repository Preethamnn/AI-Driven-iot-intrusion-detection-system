"""
Device Profile data model for the AI-driven IoT IDS system.

This module defines the DeviceProfile Pydantic model that represents
behavioral baselines and characteristics for individual IoT devices
on the network.
"""

from datetime import datetime
from typing import List, Optional, Dict, Any
from enum import Enum

from pydantic import BaseModel, Field, field_validator, model_validator


class DeviceType(str, Enum):
    """Enumeration of supported IoT device types."""
    CAMERA = "camera"
    SENSOR = "sensor"
    PLUG = "plug"
    THERMOSTAT = "thermostat"
    HUB = "hub"
    UNKNOWN = "unknown"


class ActivitySchedule(BaseModel):
    """Activity schedule representing device usage patterns."""
    hour_of_day: List[float] = Field(
        description="24-element array representing activity level (0-1) for each hour",
        min_items=24,
        max_items=24
    )
    day_of_week: List[float] = Field(
        description="7-element array representing activity level (0-1) for each day",
        min_items=7,
        max_items=7
    )
    
    @field_validator('hour_of_day', 'day_of_week')
    @classmethod
    def validate_activity_levels(cls, v):
        """Validate that activity levels are between 0 and 1."""
        for level in v:
            if not 0.0 <= level <= 1.0:
                raise ValueError(f"Activity level must be between 0.0 and 1.0, got {level}")
        return v


class DeviceProfile(BaseModel):
    """
    Device profile representing behavioral baselines for IoT devices.
    
    This model captures device identification, behavioral patterns,
    communication baselines, and learning parameters used for
    anomaly detection and threat assessment.
    """
    
    # Device Identification
    device_id: str = Field(description="Device MAC address as unique identifier")
    vendor_oui: str = Field(description="Vendor OUI prefix from MAC address")
    device_type: DeviceType = Field(description="Classified device type")
    firmware_version: Optional[str] = Field(default=None, description="Device firmware version if available")
    
    # Behavioral Baselines
    normal_protocols: List[str] = Field(
        default_factory=list,
        description="List of protocols normally used by this device"
    )
    allowed_destinations: List[str] = Field(
        default_factory=list,
        description="List of allowed destination IP ranges or domains"
    )
    typical_bandwidth_bps: int = Field(
        ge=0,
        default=0,
        description="Typical bandwidth usage in bits per second"
    )
    activity_schedule: Optional[ActivitySchedule] = Field(
        default=None,
        description="Time-based activity patterns"
    )
    
    # Learning Parameters
    profile_created: datetime = Field(description="Timestamp when profile was created")
    last_updated: datetime = Field(description="Timestamp of last profile update")
    confidence_score: float = Field(
        ge=0.0,
        le=1.0,
        description="Confidence level in the profile accuracy (0-1)"
    )
    observation_count: int = Field(
        ge=0,
        description="Number of observations used to build this profile"
    )
    
    class Config:
        """Pydantic configuration for DeviceProfile model."""
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }
        schema_extra = {
            "example": {
                "device_id": "aa:bb:cc:dd:ee:ff",
                "vendor_oui": "aa:bb:cc",
                "device_type": "camera",
                "firmware_version": "1.2.3",
                "normal_protocols": ["TCP", "UDP", "ICMP"],
                "allowed_destinations": ["192.168.1.0/24", "8.8.8.8", "*.example.com"],
                "typical_bandwidth_bps": 1048576,
                "activity_schedule": {
                    "hour_of_day": [0.1] * 6 + [0.8] * 12 + [0.3] * 6,
                    "day_of_week": [0.9, 0.9, 0.9, 0.9, 0.9, 0.5, 0.5]
                },
                "profile_created": "2024-01-15T10:00:00Z",
                "last_updated": "2024-01-15T15:30:00Z",
                "confidence_score": 0.85,
                "observation_count": 1000
            }
        }
    
    @field_validator('device_id')
    @classmethod
    def validate_mac_address(cls, v):
        """Validate MAC address format."""
        import re
        mac_pattern = re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')
        if not mac_pattern.match(v):
            raise ValueError(f"Invalid MAC address format: {v}")
        return v.lower()
    
    @field_validator('vendor_oui')
    @classmethod
    def validate_oui_format(cls, v):
        """Validate OUI format (first 3 octets of MAC address)."""
        import re
        oui_pattern = re.compile(r'^([0-9A-Fa-f]{2}[:-]){2}([0-9A-Fa-f]{2})$')
        if not oui_pattern.match(v):
            raise ValueError(f"Invalid OUI format: {v}")
        return v.lower()
    
    @field_validator('normal_protocols')
    @classmethod
    def validate_protocols(cls, v):
        """Validate that protocols are from known set."""
        valid_protocols = {
            'TCP', 'UDP', 'ICMP', 'ICMPV6', 'HTTP', 'HTTPS', 'DNS', 'DHCP', 'NTP',
            'RTSP', 'ONVIF', 'MQTT', 'COAP', 'ZIGBEE', 'Z-WAVE', 'SNMP', 'SSH', 'FTP',
            'TELNET', 'SMTP', 'POP3', 'IMAP', 'LDAP', 'RADIUS', 'SYSLOG'
        }
        for protocol in v:
            if protocol.upper() not in valid_protocols:
                raise ValueError(f"Unknown protocol: {protocol}")
        return [p.upper() for p in v]
    
    @field_validator('allowed_destinations')
    @classmethod
    def validate_destinations(cls, v):
        """Validate destination formats (IP ranges, IPs, or domain patterns)."""
        import re
        from ipaddress import ip_network, ip_address, AddressValueError
        
        if not isinstance(v, list):
            return v
        
        validated_destinations = []
        for dest in v:
            # Check if it's an IP network (CIDR notation)
            try:
                ip_network(dest, strict=False)
                validated_destinations.append(dest)
                continue
            except (AddressValueError, ValueError):
                pass
            
            # Check if it's a single IP address
            try:
                ip_address(dest)
                validated_destinations.append(dest)
                continue
            except (AddressValueError, ValueError):
                pass
            
            # Check if it's a domain pattern (allow wildcards, require at least one dot)
            # Wildcard domains: *.example.com
            # Regular domains: example.com (must have at least one dot)
            domain_pattern = re.compile(r'^(\*\.)?[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+$')
            if domain_pattern.match(dest):
                validated_destinations.append(dest)
                continue
            
            # If none of the above match, it's invalid
            raise ValueError(f"Invalid destination format: {dest}")
        
        return validated_destinations
    
    @model_validator(mode='after')
    def validate_profile_consistency(self):
        """Validate consistency between profile fields."""
        profile_created = self.profile_created
        last_updated = self.last_updated
        observation_count = self.observation_count or 0
        confidence_score = self.confidence_score or 0.0
        
        # Ensure last_updated is not before profile_created
        if profile_created and last_updated and last_updated < profile_created:
            raise ValueError("last_updated cannot be before profile_created")
        
        # Confidence should correlate with observation count
        if observation_count == 0 and confidence_score > 0.1:
            raise ValueError("Confidence score should be low when observation count is zero")
        
        return self
    
    def is_mature_profile(self, min_observations: int = 100, min_confidence: float = 0.7) -> bool:
        """Check if profile has sufficient data for reliable anomaly detection."""
        return (self.observation_count >= min_observations and 
                self.confidence_score >= min_confidence)
    
    def get_active_hours(self, threshold: float = 0.5) -> List[int]:
        """Get list of hours when device is typically active."""
        if not self.activity_schedule:
            return []
        return [hour for hour, activity in enumerate(self.activity_schedule.hour_of_day) 
                if activity >= threshold]
    
    def get_active_days(self, threshold: float = 0.5) -> List[int]:
        """Get list of days when device is typically active (0=Monday, 6=Sunday)."""
        if not self.activity_schedule:
            return []
        return [day for day, activity in enumerate(self.activity_schedule.day_of_week) 
                if activity >= threshold]
    
    def update_observation_count(self, additional_observations: int) -> None:
        """Update observation count and adjust confidence score."""
        self.observation_count += additional_observations
        self.last_updated = datetime.utcnow()
        
        # Simple confidence calculation based on observation count
        # More observations generally increase confidence, but with diminishing returns
        import math
        max_confidence = 0.95
        confidence_factor = 1 - math.exp(-self.observation_count / 1000)
        self.confidence_score = min(max_confidence, confidence_factor)