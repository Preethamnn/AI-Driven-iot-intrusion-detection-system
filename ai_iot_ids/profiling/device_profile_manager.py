"""
Device Profile Manager for the AI-driven IoT IDS system.

This module provides comprehensive device profiling capabilities including:
- Device identification from MAC/OUI
- Protocol mapping and behavioral baseline establishment  
- Time-of-day and periodicity analysis
- Profile learning and anomaly detection
"""

import asyncio
import statistics
from collections import defaultdict, Counter
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple, Any
from pathlib import Path
import json
import math

from ..models.device_profile import DeviceProfile, DeviceType, ActivitySchedule
from ..models.network_flow import NetworkFlow
from ..interfaces.feature_extractor import FeatureVector
from .oui_database import OUIDatabase
from ..utils.logging_config import get_logger
from ..utils.error_handling import IDSError


class DeviceProfileManager:
    """
    Manages device profiles for IoT devices on the network.
    
    Provides functionality for:
    - Creating device profiles from MAC/OUI identification
    - Learning behavioral baselines from network traffic
    - Analyzing time-of-day and periodicity patterns
    - Detecting anomalies based on established profiles
    """
    
    def __init__(self, config: Dict[str, Any], logger=None):
        """
        Initialize the Device Profile Manager.
        
        Args:
            config: Configuration dictionary
            logger: Optional logger instance
        """
        self.logger = logger or get_logger(__name__)
        self.config = config
        
        # Profile storage configuration
        self.profiles_path = Path(config.get('profiles_path', 'data/device_profiles'))
        self.auto_save_interval = config.get('auto_save_interval_minutes', 15)
        self.profile_learning_window_days = config.get('profile_learning_window_days', 7)
        self.min_observations_for_baseline = config.get('min_observations_for_baseline', 100)
        
        # Behavioral analysis configuration
        self.activity_window_minutes = config.get('activity_window_minutes', 60)
        self.periodicity_analysis_hours = config.get('periodicity_analysis_hours', 24)
        self.anomaly_threshold = config.get('anomaly_threshold', 0.7)
        
        # In-memory profile storage
        self.profiles: Dict[str, DeviceProfile] = {}
        self.profile_observations: Dict[str, List[Dict]] = defaultdict(list)
        self.last_save_time = datetime.utcnow()
        
        # OUI database for device identification
        oui_config = config.get('oui_database', {})
        self.oui_database = OUIDatabase(oui_config, logger)
        
        # Statistics tracking
        self.profiles_created = 0
        self.profiles_updated = 0
        self.anomalies_detected = 0
        
        # Background tasks
        self._auto_save_task: Optional[asyncio.Task] = None
        self._running = False
    
    async def initialize(self) -> None:
        """Initialize the device profile manager."""
        try:
            # Create profiles directory
            self.profiles_path.mkdir(parents=True, exist_ok=True)
            
            # Load existing profiles
            await self._load_profiles()
            
            self.logger.info(f"DeviceProfileManager initialized with {len(self.profiles)} profiles")
            
        except Exception as e:
            raise IDSError(f"Failed to initialize DeviceProfileManager: {e}")
    
    async def start(self) -> None:
        """Start the device profile manager."""
        if not self._running:
            self._running = True
            
            # Start auto-save task
            if self.auto_save_interval > 0:
                self._auto_save_task = asyncio.create_task(self._auto_save_loop())
            
            self.logger.info("DeviceProfileManager started")
    
    async def stop(self) -> None:
        """Stop the device profile manager."""
        self._running = False
        
        # Cancel auto-save task
        if self._auto_save_task:
            self._auto_save_task.cancel()
            try:
                await self._auto_save_task
            except asyncio.CancelledError:
                pass
        
        # Save all profiles before stopping
        await self._save_profiles()
        
        self.logger.info("DeviceProfileManager stopped")
    
    async def create_device_profile(self, mac_address: str, 
                                  initial_flows: Optional[List[NetworkFlow]] = None) -> DeviceProfile:
        """
        Create a new device profile from MAC address identification.
        
        Args:
            mac_address: Device MAC address
            initial_flows: Optional initial network flows for baseline establishment
            
        Returns:
            Created DeviceProfile object
        """
        try:
            # Extract OUI and get vendor information
            oui = self.oui_database.extract_oui(mac_address)
            vendor = self.oui_database.get_vendor(mac_address)
            device_type = self.oui_database.infer_device_type(mac_address, vendor)
            
            # Get default protocols and bandwidth for device type
            normal_protocols = list(self.oui_database.get_device_protocols(device_type))
            typical_bandwidth = self.oui_database.get_typical_bandwidth(device_type)
            
            # Create default activity schedule
            hour_activity, day_activity = self.oui_database.get_default_activity_schedule(device_type)
            activity_schedule = ActivitySchedule(
                hour_of_day=hour_activity,
                day_of_week=day_activity
            )
            
            # Create device profile
            now = datetime.utcnow()
            profile = DeviceProfile(
                device_id=mac_address.lower(),
                vendor_oui=oui,
                device_type=device_type,
                normal_protocols=normal_protocols,
                typical_bandwidth_bps=typical_bandwidth,
                activity_schedule=activity_schedule,
                profile_created=now,
                last_updated=now,
                confidence_score=0.1,  # Low initial confidence
                observation_count=0
            )
            
            # If initial flows provided, update profile with them
            if initial_flows:
                await self._update_profile_from_flows(profile, initial_flows)
            
            # Store profile
            self.profiles[mac_address.lower()] = profile
            self.profiles_created += 1
            
            self.logger.info(f"Created device profile for {mac_address} (vendor: {vendor}, type: {device_type.value})")
            
            return profile
            
        except Exception as e:
            raise IDSError(f"Failed to create device profile for {mac_address}: {e}")
    
    async def update_device_profile(self, mac_address: str, 
                                  flows: List[NetworkFlow]) -> DeviceProfile:
        """
        Update device profile with new network flow observations.
        
        Args:
            mac_address: Device MAC address
            flows: New network flows to incorporate into profile
            
        Returns:
            Updated DeviceProfile object
        """
        mac_lower = mac_address.lower()
        
        # Get or create profile
        if mac_lower not in self.profiles:
            profile = await self.create_device_profile(mac_address, flows)
        else:
            profile = self.profiles[mac_lower]
            await self._update_profile_from_flows(profile, flows)
        
        self.profiles_updated += 1
        return profile
    
    async def _update_profile_from_flows(self, profile: DeviceProfile, 
                                       flows: List[NetworkFlow]) -> None:
        """
        Update profile behavioral baselines from network flows.
        
        Args:
            profile: Device profile to update
            flows: Network flows to analyze
        """
        if not flows:
            return
        
        # Store observations for later analysis
        device_id = profile.device_id
        for flow in flows:
            observation = {
                'timestamp': flow.timestamp,
                'protocol': flow.protocol,
                'destination_ip': flow.destination_ip,
                'destination_port': flow.destination_port,
                'bytes_total': flow.total_bytes(),
                'duration_ms': flow.duration_ms,
                'packets_total': flow.total_packets()
            }
            self.profile_observations[device_id].append(observation)
        
        # Keep only recent observations within learning window
        cutoff_time = datetime.utcnow() - timedelta(days=self.profile_learning_window_days)
        self.profile_observations[device_id] = [
            obs for obs in self.profile_observations[device_id]
            if obs['timestamp'] > cutoff_time
        ]
        
        observations = self.profile_observations[device_id]
        
        # Update protocol baseline
        await self._update_protocol_baseline(profile, observations)
        
        # Update destination allowlist
        await self._update_destination_allowlist(profile, observations)
        
        # Update bandwidth baseline
        await self._update_bandwidth_baseline(profile, observations)
        
        # Update activity schedule
        await self._update_activity_schedule(profile, observations)
        
        # Update profile metadata
        profile.observation_count = len(observations)
        profile.last_updated = datetime.utcnow()
        
        # Update confidence score based on observation count and consistency
        await self._update_confidence_score(profile, observations)
    
    async def _update_protocol_baseline(self, profile: DeviceProfile, 
                                      observations: List[Dict]) -> None:
        """Update normal protocols baseline from observations."""
        if not observations:
            return
        
        # Count protocol usage
        protocol_counts = Counter(obs['protocol'] for obs in observations)
        total_observations = len(observations)
        
        # If we have enough observations (>= 10), learn protocols from actual data
        # and replace OUI defaults. Otherwise, keep OUI defaults and add observed protocols.
        if total_observations >= 10:
            # Replace with learned protocols (protocols used in >5% of observations)
            normal_protocols = set()
            for protocol, count in protocol_counts.items():
                usage_ratio = count / total_observations
                if usage_ratio > 0.05:  # 5% threshold
                    normal_protocols.add(protocol.upper())
            
            # Ensure at least one protocol is present
            if not normal_protocols and protocol_counts:
                # Add the most common protocol
                most_common = protocol_counts.most_common(1)[0][0]
                normal_protocols.add(most_common.upper())
        else:
            # Keep OUI defaults and add observed protocols
            normal_protocols = set(profile.normal_protocols)
            for protocol, count in protocol_counts.items():
                usage_ratio = count / total_observations
                if usage_ratio > 0.05:  # 5% threshold
                    normal_protocols.add(protocol.upper())
        
        profile.normal_protocols = sorted(list(normal_protocols))
    
    async def _update_destination_allowlist(self, profile: DeviceProfile, 
                                          observations: List[Dict]) -> None:
        """Update allowed destinations from observations."""
        if not observations:
            return
        
        # Collect unique destinations
        destinations = set(obs['destination_ip'] for obs in observations)
        
        # Convert to network ranges where possible (simplified approach)
        allowed_destinations = set(profile.allowed_destinations)
        for dest_ip in destinations:
            # For now, add individual IPs (could be enhanced to detect subnets)
            allowed_destinations.add(dest_ip)
        
        # Limit to reasonable number of destinations
        max_destinations = 100
        if len(allowed_destinations) > max_destinations:
            # Keep most frequently accessed destinations
            dest_counts = Counter(obs['destination_ip'] for obs in observations)
            top_destinations = [dest for dest, _ in dest_counts.most_common(max_destinations)]
            allowed_destinations = set(top_destinations)
        
        profile.allowed_destinations = sorted(list(allowed_destinations))
    
    async def _update_bandwidth_baseline(self, profile: DeviceProfile, 
                                       observations: List[Dict]) -> None:
        """Update typical bandwidth from observations."""
        if not observations:
            return
        
        # Calculate bandwidth from recent observations
        recent_observations = observations[-100:]  # Last 100 observations
        
        if len(recent_observations) < 10:
            return  # Need minimum observations
        
        # Calculate bytes per time unit
        bandwidth_samples = []
        for obs in recent_observations:
            if obs['duration_ms'] > 0:
                # Calculate bps for this flow
                bytes_total = obs['bytes_total']
                duration_seconds = obs['duration_ms'] / 1000.0
                bps = (bytes_total * 8) / duration_seconds
                bandwidth_samples.append(bps)
        
        if bandwidth_samples:
            # Use median to avoid outliers
            typical_bandwidth = int(statistics.median(bandwidth_samples))
            
            # Smooth update with existing value
            current_bandwidth = profile.typical_bandwidth_bps
            if current_bandwidth > 0:
                # Calculate difference ratio to determine update weight
                diff_ratio = abs(typical_bandwidth - current_bandwidth) / max(current_bandwidth, 1)
                
                # If difference is large (>50%), trust new data more
                if diff_ratio > 0.5:
                    # Weighted average: 30% old, 70% new (trust new data)
                    profile.typical_bandwidth_bps = int(0.3 * current_bandwidth + 0.7 * typical_bandwidth)
                else:
                    # Weighted average: 70% old, 30% new (smooth update)
                    profile.typical_bandwidth_bps = int(0.7 * current_bandwidth + 0.3 * typical_bandwidth)
            else:
                profile.typical_bandwidth_bps = typical_bandwidth
    
    async def _update_activity_schedule(self, profile: DeviceProfile, 
                                      observations: List[Dict]) -> None:
        """Update activity schedule from temporal patterns in observations."""
        if len(observations) < 24:  # Need minimum observations
            return
        
        # Initialize activity counters
        hour_counts = [0] * 24
        day_counts = [0] * 7
        
        # Count observations by hour and day
        for obs in observations:
            timestamp = obs['timestamp']
            hour = timestamp.hour
            day = timestamp.weekday()  # 0=Monday, 6=Sunday
            
            hour_counts[hour] += 1
            day_counts[day] += 1
        
        # Normalize to activity levels (0-1)
        max_hour_count = max(hour_counts) if max(hour_counts) > 0 else 1
        max_day_count = max(day_counts) if max(day_counts) > 0 else 1
        
        hour_activity = [count / max_hour_count for count in hour_counts]
        day_activity = [count / max_day_count for count in day_counts]
        
        # Smooth with existing schedule if available
        if profile.activity_schedule:
            existing_hour = profile.activity_schedule.hour_of_day
            existing_day = profile.activity_schedule.day_of_week
            
            # Weighted average: 60% old, 40% new
            hour_activity = [0.6 * old + 0.4 * new for old, new in zip(existing_hour, hour_activity)]
            day_activity = [0.6 * old + 0.4 * new for old, new in zip(existing_day, day_activity)]
        
        # Update activity schedule
        profile.activity_schedule = ActivitySchedule(
            hour_of_day=hour_activity,
            day_of_week=day_activity
        )
    
    async def _update_confidence_score(self, profile: DeviceProfile, 
                                     observations: List[Dict]) -> None:
        """Update profile confidence score based on observation quality and quantity."""
        observation_count = len(observations)
        
        # Base confidence from observation count (logarithmic growth)
        count_confidence = min(0.9, math.log1p(observation_count) / 10.0)
        
        # Consistency confidence from protocol usage
        if observations:
            protocols = [obs['protocol'] for obs in observations]
            protocol_counts = Counter(protocols)
            protocol_entropy = self._calculate_entropy(list(protocol_counts.values()))
            
            # Lower entropy (more consistent) = higher confidence
            max_entropy = math.log2(len(protocol_counts)) if len(protocol_counts) > 1 else 1
            consistency_confidence = 1.0 - (protocol_entropy / max_entropy) if max_entropy > 0 else 1.0
        else:
            consistency_confidence = 0.0
        
        # Temporal consistency confidence
        if len(observations) > 24:
            timestamps = [obs['timestamp'] for obs in observations[-24:]]  # Last 24 observations
            time_deltas = []
            for i in range(1, len(timestamps)):
                delta = (timestamps[i] - timestamps[i-1]).total_seconds()
                time_deltas.append(delta)
            
            if time_deltas:
                # Lower coefficient of variation = higher temporal consistency
                mean_delta = statistics.mean(time_deltas)
                std_delta = statistics.stdev(time_deltas) if len(time_deltas) > 1 else 0
                cv = std_delta / mean_delta if mean_delta > 0 else 1
                temporal_confidence = 1.0 / (1.0 + cv)
            else:
                temporal_confidence = 0.5
        else:
            temporal_confidence = 0.5
        
        # Combined confidence score
        profile.confidence_score = (count_confidence * 0.5 + 
                                  consistency_confidence * 0.3 + 
                                  temporal_confidence * 0.2)
    
    async def analyze_periodicity(self, device_id: str, 
                                hours_back: int = 24) -> Dict[str, float]:
        """
        Analyze periodicity patterns for a device.
        
        Args:
            device_id: Device identifier (MAC address)
            hours_back: Hours of history to analyze
            
        Returns:
            Dictionary containing periodicity analysis results
        """
        device_id_lower = device_id.lower()
        
        if device_id_lower not in self.profile_observations:
            return {}
        
        observations = self.profile_observations[device_id_lower]
        
        # Filter to recent observations
        cutoff_time = datetime.utcnow() - timedelta(hours=hours_back)
        recent_obs = [obs for obs in observations if obs['timestamp'] > cutoff_time]
        
        if len(recent_obs) < 10:
            return {'insufficient_data': True}
        
        # Sort by timestamp
        recent_obs.sort(key=lambda x: x['timestamp'])
        
        # Calculate inter-arrival times
        inter_arrivals = []
        for i in range(1, len(recent_obs)):
            delta = (recent_obs[i]['timestamp'] - recent_obs[i-1]['timestamp']).total_seconds()
            inter_arrivals.append(delta)
        
        if not inter_arrivals:
            return {'no_intervals': True}
        
        # Periodicity analysis
        mean_interval = statistics.mean(inter_arrivals)
        std_interval = statistics.stdev(inter_arrivals) if len(inter_arrivals) > 1 else 0
        
        # Coefficient of variation (lower = more periodic)
        cv = std_interval / mean_interval if mean_interval > 0 else float('inf')
        periodicity_score = 1.0 / (1.0 + cv)  # Higher score = more periodic
        
        # Detect common periods (hourly, daily patterns)
        hourly_pattern = self._detect_hourly_pattern(recent_obs)
        daily_pattern = self._detect_daily_pattern(recent_obs)
        
        return {
            'mean_interval_seconds': mean_interval,
            'std_interval_seconds': std_interval,
            'coefficient_of_variation': cv,
            'periodicity_score': periodicity_score,
            'hourly_pattern_strength': hourly_pattern,
            'daily_pattern_strength': daily_pattern,
            'observation_count': len(recent_obs),
            'analysis_window_hours': hours_back
        }
    
    def _detect_hourly_pattern(self, observations: List[Dict]) -> float:
        """Detect hourly activity patterns."""
        if len(observations) < 24:
            return 0.0
        
        # Count observations by hour
        hour_counts = [0] * 24
        for obs in observations:
            hour = obs['timestamp'].hour
            hour_counts[hour] += 1
        
        # Calculate pattern strength (entropy-based)
        total_obs = sum(hour_counts)
        if total_obs == 0:
            return 0.0
        
        # Normalize and calculate entropy
        hour_probs = [count / total_obs for count in hour_counts]
        entropy = self._calculate_entropy(hour_probs)
        max_entropy = math.log2(24)  # Maximum possible entropy for 24 hours
        
        # Pattern strength: 1 - normalized_entropy
        pattern_strength = 1.0 - (entropy / max_entropy)
        return max(0.0, pattern_strength)
    
    def _detect_daily_pattern(self, observations: List[Dict]) -> float:
        """Detect daily activity patterns."""
        if len(observations) < 7:
            return 0.0
        
        # Count observations by day of week
        day_counts = [0] * 7
        for obs in observations:
            day = obs['timestamp'].weekday()
            day_counts[day] += 1
        
        # Calculate pattern strength
        total_obs = sum(day_counts)
        if total_obs == 0:
            return 0.0
        
        day_probs = [count / total_obs for count in day_counts]
        entropy = self._calculate_entropy(day_probs)
        max_entropy = math.log2(7)  # Maximum possible entropy for 7 days
        
        pattern_strength = 1.0 - (entropy / max_entropy)
        return max(0.0, pattern_strength)
    
    async def detect_anomalies(self, device_id: str, 
                             recent_flows: List[NetworkFlow]) -> List[Dict[str, Any]]:
        """
        Detect anomalies based on established device profile.
        
        Args:
            device_id: Device identifier (MAC address)
            recent_flows: Recent network flows to analyze
            
        Returns:
            List of detected anomalies with details
        """
        device_id_lower = device_id.lower()
        
        if device_id_lower not in self.profiles:
            return []  # No profile available
        
        profile = self.profiles[device_id_lower]
        
        if not profile.is_mature_profile():
            return []  # Profile not mature enough for reliable anomaly detection
        
        anomalies = []
        
        for flow in recent_flows:
            flow_anomalies = await self._detect_flow_anomalies(profile, flow)
            anomalies.extend(flow_anomalies)
        
        # Update anomaly statistics
        self.anomalies_detected += len(anomalies)
        
        return anomalies
    
    async def _detect_flow_anomalies(self, profile: DeviceProfile, 
                                   flow: NetworkFlow) -> List[Dict[str, Any]]:
        """Detect anomalies in a single network flow."""
        anomalies = []
        
        # Protocol anomaly detection
        if flow.protocol.upper() not in profile.normal_protocols:
            anomalies.append({
                'type': 'protocol_anomaly',
                'severity': 'medium',
                'description': f'Unusual protocol {flow.protocol} for device type {profile.device_type.value}',
                'flow_id': getattr(flow, 'flow_id', 'unknown'),
                'timestamp': flow.timestamp,
                'details': {
                    'observed_protocol': flow.protocol,
                    'normal_protocols': profile.normal_protocols
                }
            })
        
        # Destination anomaly detection
        if (profile.allowed_destinations and 
            flow.destination_ip not in profile.allowed_destinations):
            anomalies.append({
                'type': 'destination_anomaly',
                'severity': 'high',
                'description': f'Communication to unauthorized destination {flow.destination_ip}',
                'flow_id': getattr(flow, 'flow_id', 'unknown'),
                'timestamp': flow.timestamp,
                'details': {
                    'destination_ip': flow.destination_ip,
                    'allowed_destinations_count': len(profile.allowed_destinations)
                }
            })
        
        # Bandwidth anomaly detection
        if profile.typical_bandwidth_bps > 0:
            flow_bandwidth = flow.total_bytes() * 8 / (flow.duration_ms / 1000.0) if flow.duration_ms > 0 else 0
            bandwidth_ratio = flow_bandwidth / profile.typical_bandwidth_bps
            
            if bandwidth_ratio > 5.0:  # 5x normal bandwidth
                anomalies.append({
                    'type': 'bandwidth_anomaly',
                    'severity': 'medium',
                    'description': f'Unusually high bandwidth usage: {flow_bandwidth:.0f} bps vs typical {profile.typical_bandwidth_bps:.0f} bps',
                    'flow_id': getattr(flow, 'flow_id', 'unknown'),
                    'timestamp': flow.timestamp,
                    'details': {
                        'observed_bandwidth_bps': flow_bandwidth,
                        'typical_bandwidth_bps': profile.typical_bandwidth_bps,
                        'ratio': bandwidth_ratio
                    }
                })
        
        # Time-of-day anomaly detection
        if profile.activity_schedule:
            hour = flow.timestamp.hour
            expected_activity = profile.activity_schedule.hour_of_day[hour]
            
            if expected_activity < 0.2:  # Low expected activity
                anomalies.append({
                    'type': 'temporal_anomaly',
                    'severity': 'low',
                    'description': f'Activity during typically inactive hour {hour}:00',
                    'flow_id': getattr(flow, 'flow_id', 'unknown'),
                    'timestamp': flow.timestamp,
                    'details': {
                        'hour': hour,
                        'expected_activity': expected_activity
                    }
                })
        
        return anomalies
    
    async def get_device_profile(self, device_id: str) -> Optional[DeviceProfile]:
        """
        Get device profile by device ID.
        
        Args:
            device_id: Device identifier (MAC address)
            
        Returns:
            DeviceProfile if found, None otherwise
        """
        return self.profiles.get(device_id.lower())
    
    async def list_device_profiles(self, device_type: Optional[DeviceType] = None) -> List[DeviceProfile]:
        """
        List all device profiles, optionally filtered by device type.
        
        Args:
            device_type: Optional device type filter
            
        Returns:
            List of matching device profiles
        """
        profiles = list(self.profiles.values())
        
        if device_type:
            profiles = [p for p in profiles if p.device_type == device_type]
        
        return profiles
    
    async def delete_device_profile(self, device_id: str) -> bool:
        """
        Delete a device profile.
        
        Args:
            device_id: Device identifier (MAC address)
            
        Returns:
            True if profile was deleted, False if not found
        """
        device_id_lower = device_id.lower()
        
        if device_id_lower in self.profiles:
            del self.profiles[device_id_lower]
            
            # Also remove observations
            if device_id_lower in self.profile_observations:
                del self.profile_observations[device_id_lower]
            
            # Remove profile file
            profile_file = self.profiles_path / f"{device_id_lower}.json"
            if profile_file.exists():
                profile_file.unlink()
            
            self.logger.info(f"Deleted device profile for {device_id}")
            return True
        
        return False
    
    async def get_statistics(self) -> Dict[str, Any]:
        """
        Get device profile manager statistics.
        
        Returns:
            Dictionary containing statistics
        """
        # Device type distribution
        type_counts = Counter(p.device_type.value for p in self.profiles.values())
        
        # Confidence distribution
        confidence_scores = [p.confidence_score for p in self.profiles.values()]
        avg_confidence = statistics.mean(confidence_scores) if confidence_scores else 0.0
        
        # Maturity analysis
        mature_profiles = sum(1 for p in self.profiles.values() if p.is_mature_profile())
        
        return {
            'total_profiles': len(self.profiles),
            'profiles_created': self.profiles_created,
            'profiles_updated': self.profiles_updated,
            'anomalies_detected': self.anomalies_detected,
            'device_type_distribution': dict(type_counts),
            'average_confidence_score': avg_confidence,
            'mature_profiles': mature_profiles,
            'maturity_rate': mature_profiles / len(self.profiles) if self.profiles else 0.0,
            'total_observations': sum(len(obs) for obs in self.profile_observations.values()),
            'oui_database_stats': self.oui_database.get_statistics()
        }
    
    async def _load_profiles(self) -> None:
        """Load device profiles from disk."""
        if not self.profiles_path.exists():
            return
        
        loaded_count = 0
        for profile_file in self.profiles_path.glob("*.json"):
            try:
                with open(profile_file, 'r', encoding='utf-8') as f:
                    profile_data = json.load(f)
                    profile = DeviceProfile(**profile_data)
                    self.profiles[profile.device_id] = profile
                    loaded_count += 1
            except Exception as e:
                self.logger.warning(f"Failed to load profile from {profile_file}: {e}")
        
        if loaded_count > 0:
            self.logger.info(f"Loaded {loaded_count} device profiles from disk")
    
    async def _save_profiles(self) -> None:
        """Save device profiles to disk."""
        try:
            self.profiles_path.mkdir(parents=True, exist_ok=True)
            
            saved_count = 0
            for device_id, profile in self.profiles.items():
                # Sanitize device_id for filename (replace colons with hyphens for Windows compatibility)
                safe_filename = device_id.replace(':', '-')
                profile_file = self.profiles_path / f"{safe_filename}.json"
                
                try:
                    with open(profile_file, 'w', encoding='utf-8') as f:
                        json.dump(profile.dict(), f, indent=2, default=str)
                    saved_count += 1
                except Exception as e:
                    self.logger.error(f"Failed to save profile for {device_id}: {e}")
            
            self.last_save_time = datetime.utcnow()
            self.logger.debug(f"Saved {saved_count} device profiles to disk")
            
        except Exception as e:
            self.logger.error(f"Failed to save profiles: {e}")
    
    async def _auto_save_loop(self) -> None:
        """Background task for automatic profile saving."""
        while self._running:
            try:
                await asyncio.sleep(self.auto_save_interval * 60)  # Convert minutes to seconds
                if self._running:
                    await self._save_profiles()
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Error in auto-save loop: {e}")
    
    def _calculate_entropy(self, values: List[float]) -> float:
        """Calculate Shannon entropy of a list of probability values."""
        if not values:
            return 0.0
        
        # Filter out zero values
        non_zero_values = [v for v in values if v > 0]
        if not non_zero_values:
            return 0.0
        
        # Normalize to probabilities
        total = sum(non_zero_values)
        probabilities = [v / total for v in non_zero_values]
        
        # Calculate entropy
        entropy = 0.0
        for p in probabilities:
            if p > 0:
                entropy -= p * math.log2(p)
        
        return entropy