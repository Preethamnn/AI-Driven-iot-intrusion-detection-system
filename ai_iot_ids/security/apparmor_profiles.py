"""AppArmor profile management for IoT IDS."""

import os
import logging
import subprocess
from typing import Dict, List, Optional, Any
from pathlib import Path

logger = logging.getLogger(__name__)


class AppArmorProfileManager:
    """Manages AppArmor profiles for IoT IDS components."""
    
    def __init__(self, profile_dir: str = "/etc/apparmor.d"):
        """Initialize AppArmor profile manager.
        
        Args:
            profile_dir: Directory containing AppArmor profiles
        """
        self.profile_dir = Path(profile_dir)
        self.profile_name = "iot-ids-profile"
        
    def create_edge_gateway_profile(self) -> str:
        """Create AppArmor profile for edge gateway component.
        
        Returns:
            AppArmor profile content as string
        """
        profile_content = f"""#include <tunables/global>

/usr/bin/python3 {{
  #include <abstractions/base>
  #include <abstractions/python>
  #include <abstractions/nameservice>
  
  # Capabilities needed for packet capture
  capability net_raw,
  capability net_admin,
  capability dac_override,
  
  # Network access
  network inet dgram,
  network inet stream,
  network inet6 dgram,
  network inet6 stream,
  network packet raw,
  
  # File system access - read-only for most paths
  / r,
  /etc/ r,
  /etc/** r,
  /usr/ r,
  /usr/** r,
  /lib/ r,
  /lib/** r,
  /lib64/ r,
  /lib64/** r,
  /bin/ r,
  /bin/** r,
  /sbin/ r,
  /sbin/** r,
  
  # Writable directories
  /tmp/ rw,
  /tmp/** rw,
  /var/tmp/ rw,
  /var/tmp/** rw,
  /var/log/iot-ids/ rw,
  /var/log/iot-ids/** rw,
  /var/run/iot-ids/ rw,
  /var/run/iot-ids/** rw,
  
  # Application directory
  /app/ r,
  /app/** r,
  
  # Python specific
  /usr/bin/python3 ix,
  /usr/lib/python3*/** r,
  
  # Proc and sys access (limited)
  /proc/sys/net/core/rmem_max r,
  /proc/sys/net/core/wmem_max r,
  /proc/net/dev r,
  /sys/class/net/ r,
  /sys/class/net/** r,
  
  # Device access for packet capture
  /dev/urandom r,
  /dev/random r,
  
  # Deny dangerous operations
  deny /proc/sys/** w,
  deny /sys/** w,
  deny mount,
  deny umount,
  deny pivot_root,
  deny ptrace,
  deny signal,
  
  # Deny access to sensitive files
  deny /etc/shadow r,
  deny /etc/passwd w,
  deny /etc/group w,
  deny /root/** rw,
  deny /home/*/.ssh/** rw,
}}"""
        
        return profile_content
        
    def create_ai_service_profile(self) -> str:
        """Create AppArmor profile for AI inference service.
        
        Returns:
            AppArmor profile content as string
        """
        profile_content = f"""#include <tunables/global>

/usr/bin/python3 {{
  #include <abstractions/base>
  #include <abstractions/python>
  #include <abstractions/nameservice>
  
  # Network access for API endpoints
  network inet dgram,
  network inet stream,
  network inet6 dgram,
  network inet6 stream,
  
  # File system access - read-only for most paths
  / r,
  /etc/ r,
  /etc/** r,
  /usr/ r,
  /usr/** r,
  /lib/ r,
  /lib/** r,
  /lib64/ r,
  /lib64/** r,
  /bin/ r,
  /bin/** r,
  /sbin/ r,
  /sbin/** r,
  
  # Writable directories
  /tmp/ rw,
  /tmp/** rw,
  /var/tmp/ rw,
  /var/tmp/** rw,
  /var/log/iot-ids/ rw,
  /var/log/iot-ids/** rw,
  /var/run/iot-ids/ rw,
  /var/run/iot-ids/** rw,
  
  # Application and model directories
  /app/ r,
  /app/** r,
  /models/ r,
  /models/** r,
  
  # Python and ML libraries
  /usr/bin/python3 ix,
  /usr/lib/python3*/** r,
  
  # GPU access if available (for ML inference)
  /dev/nvidia* rw,
  /proc/driver/nvidia/** r,
  
  # Deny dangerous operations
  deny /proc/sys/** w,
  deny /sys/** w,
  deny mount,
  deny umount,
  deny pivot_root,
  deny ptrace,
  deny signal,
  
  # Deny access to sensitive files
  deny /etc/shadow r,
  deny /etc/passwd w,
  deny /etc/group w,
  deny /root/** rw,
  deny /home/*/.ssh/** rw,
}}"""
        
        return profile_content
        
    def install_profiles(self) -> bool:
        """Install AppArmor profiles to the system.
        
        Returns:
            True if profiles were installed successfully
        """
        try:
            if not self._is_apparmor_available():
                logger.warning("AppArmor is not available on this system")
                return False
                
            # Create profile directory if it doesn't exist
            self.profile_dir.mkdir(parents=True, exist_ok=True)
            
            # Install edge gateway profile
            edge_profile_path = self.profile_dir / f"{self.profile_name}-edge"
            with open(edge_profile_path, 'w') as f:
                f.write(self.create_edge_gateway_profile())
                
            # Install AI service profile
            ai_profile_path = self.profile_dir / f"{self.profile_name}-ai"
            with open(ai_profile_path, 'w') as f:
                f.write(self.create_ai_service_profile())
                
            # Load profiles
            self._load_profile(edge_profile_path)
            self._load_profile(ai_profile_path)
            
            logger.info("AppArmor profiles installed successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to install AppArmor profiles: {e}")
            return False
            
    def enable_profile(self, profile_name: str) -> bool:
        """Enable an AppArmor profile.
        
        Args:
            profile_name: Name of the profile to enable
            
        Returns:
            True if profile was enabled successfully
        """
        try:
            result = subprocess.run([
                'aa-enforce', profile_name
            ], capture_output=True, text=True, check=True)
            
            logger.info(f"Enabled AppArmor profile: {profile_name}")
            return True
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to enable AppArmor profile {profile_name}: {e}")
            return False
            
    def disable_profile(self, profile_name: str) -> bool:
        """Disable an AppArmor profile.
        
        Args:
            profile_name: Name of the profile to disable
            
        Returns:
            True if profile was disabled successfully
        """
        try:
            result = subprocess.run([
                'aa-disable', profile_name
            ], capture_output=True, text=True, check=True)
            
            logger.info(f"Disabled AppArmor profile: {profile_name}")
            return True
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to disable AppArmor profile {profile_name}: {e}")
            return False
            
    def get_profile_status(self, profile_name: str) -> Optional[str]:
        """Get the status of an AppArmor profile.
        
        Args:
            profile_name: Name of the profile to check
            
        Returns:
            Profile status string or None if not found
        """
        try:
            result = subprocess.run([
                'aa-status', '--json'
            ], capture_output=True, text=True, check=True)
            
            import json
            status_data = json.loads(result.stdout)
            
            # Check in different status categories
            for category in ['profiles', 'processes']:
                if category in status_data:
                    for profile in status_data[category]:
                        if profile_name in profile:
                            return status_data[category][profile]
                            
            return None
            
        except Exception as e:
            logger.error(f"Failed to get AppArmor profile status: {e}")
            return None
            
    def validate_profile_syntax(self, profile_content: str) -> bool:
        """Validate AppArmor profile syntax.
        
        Args:
            profile_content: Profile content to validate
            
        Returns:
            True if syntax is valid
        """
        try:
            # Write profile to temporary file
            import tempfile
            with tempfile.NamedTemporaryFile(mode='w', suffix='.apparmor', delete=False) as f:
                f.write(profile_content)
                temp_path = f.name
                
            try:
                # Use apparmor_parser to validate syntax
                result = subprocess.run([
                    'apparmor_parser', '-Q', temp_path
                ], capture_output=True, text=True)
                
                return result.returncode == 0
                
            finally:
                os.unlink(temp_path)
                
        except Exception as e:
            logger.error(f"Failed to validate AppArmor profile syntax: {e}")
            return False
            
    def _is_apparmor_available(self) -> bool:
        """Check if AppArmor is available on the system."""
        return os.path.exists('/sys/kernel/security/apparmor')
        
    def _load_profile(self, profile_path: Path) -> bool:
        """Load an AppArmor profile.
        
        Args:
            profile_path: Path to the profile file
            
        Returns:
            True if profile was loaded successfully
        """
        try:
            result = subprocess.run([
                'apparmor_parser', '-r', str(profile_path)
            ], capture_output=True, text=True, check=True)
            
            logger.info(f"Loaded AppArmor profile: {profile_path}")
            return True
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to load AppArmor profile {profile_path}: {e}")
            return False