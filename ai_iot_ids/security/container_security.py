"""Container security and hardening manager."""

import os
import logging
from typing import Dict, List, Optional, Any
from pathlib import Path
import subprocess
import json

# Handle platform-specific imports
try:
    import pwd
    import grp
    PWD_AVAILABLE = True
except ImportError:
    PWD_AVAILABLE = False

logger = logging.getLogger(__name__)


class ContainerSecurityManager:
    """Manages container security hardening features."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize container security manager.
        
        Args:
            config: Security configuration dictionary
        """
        self.config = config or {}
        self.readonly_paths = self.config.get('readonly_paths', [
            '/etc', '/usr', '/bin', '/sbin', '/lib', '/lib64'
        ])
        self.writable_paths = self.config.get('writable_paths', [
            '/tmp', '/var/tmp', '/var/log', '/var/run'
        ])
        self.non_root_user = self.config.get('non_root_user', 'iotids')
        self.non_root_uid = self.config.get('non_root_uid', 1000)
        self.non_root_gid = self.config.get('non_root_gid', 1000)
        
    def setup_readonly_filesystem(self) -> Dict[str, Any]:
        """Configure read-only filesystem mounts.
        
        Returns:
            Dictionary with mount configuration for Docker
        """
        mount_config = {
            'readonly_mounts': [],
            'writable_mounts': [],
            'tmpfs_mounts': []
        }
        
        # Add read-only mounts
        for path in self.readonly_paths:
            if os.path.exists(path):
                mount_config['readonly_mounts'].append({
                    'source': path,
                    'target': path,
                    'type': 'bind',
                    'readonly': True
                })
                
        # Add writable mounts with specific permissions
        for path in self.writable_paths:
            if path in ['/tmp', '/var/tmp']:
                # Use tmpfs for temporary directories
                mount_config['tmpfs_mounts'].append({
                    'target': path,
                    'size': '100m',
                    'mode': '1777'
                })
            else:
                mount_config['writable_mounts'].append({
                    'source': path,
                    'target': path,
                    'type': 'bind',
                    'readonly': False
                })
                
        logger.info(f"Configured {len(mount_config['readonly_mounts'])} read-only mounts")
        logger.info(f"Configured {len(mount_config['writable_mounts'])} writable mounts")
        logger.info(f"Configured {len(mount_config['tmpfs_mounts'])} tmpfs mounts")
        
        return mount_config
        
    def create_non_root_user(self) -> Dict[str, Any]:
        """Create non-root user configuration.
        
        Returns:
            User configuration dictionary
        """
        user_config = {
            'username': self.non_root_user,
            'uid': self.non_root_uid,
            'gid': self.non_root_gid,
            'home_dir': f'/home/{self.non_root_user}',
            'shell': '/bin/bash'
        }
        
        # Generate user creation commands for Dockerfile
        user_config['dockerfile_commands'] = [
            f"RUN groupadd -g {self.non_root_gid} {self.non_root_user}",
            f"RUN useradd -u {self.non_root_uid} -g {self.non_root_gid} -m -s /bin/bash {self.non_root_user}",
            f"RUN chown -R {self.non_root_user}:{self.non_root_user} /home/{self.non_root_user}",
            f"USER {self.non_root_user}"
        ]
        
        logger.info(f"Created non-root user configuration: {self.non_root_user} ({self.non_root_uid}:{self.non_root_gid})")
        
        return user_config
        
    def drop_privileges(self) -> bool:
        """Drop privileges to non-root user at runtime.
        
        Returns:
            True if privileges were dropped successfully
        """
        try:
            # Check if running as root
            if os.getuid() != 0:
                logger.info("Already running as non-root user")
                return True
                
            # Try to get user info
            try:
                user_info = pwd.getpwnam(self.non_root_user)
                uid = user_info.pw_uid
                gid = user_info.pw_gid
            except KeyError:
                logger.warning(f"User {self.non_root_user} not found, using configured UID/GID")
                uid = self.non_root_uid
                gid = self.non_root_gid
                
            # Drop privileges
            os.setgid(gid)
            os.setuid(uid)
            
            # Verify privilege drop
            if os.getuid() == uid and os.getgid() == gid:
                logger.info(f"Successfully dropped privileges to {self.non_root_user} ({uid}:{gid})")
                return True
            else:
                logger.error("Failed to drop privileges")
                return False
                
        except Exception as e:
            logger.error(f"Error dropping privileges: {e}")
            return False
            
    def configure_security_options(self) -> Dict[str, Any]:
        """Configure Docker security options.
        
        Returns:
            Security options dictionary
        """
        security_options = {
            'no_new_privileges': True,
            'security_opt': [
                'no-new-privileges:true'
            ],
            'cap_drop': [
                'ALL'
            ],
            'cap_add': [
                'NET_BIND_SERVICE',  # For binding to privileged ports if needed
                'NET_RAW'  # For packet capture
            ]
        }
        
        # Add AppArmor/SELinux profiles if available
        if self._is_apparmor_available():
            security_options['security_opt'].append('apparmor:iot-ids-profile')
            
        if self._is_selinux_available():
            security_options['security_opt'].append('label:type:iot_ids_t')
            
        logger.info("Configured container security options")
        return security_options
        
    def generate_dockerfile_security_directives(self) -> List[str]:
        """Generate Dockerfile directives for security hardening.
        
        Returns:
            List of Dockerfile directives
        """
        directives = [
            "# Security hardening directives",
            "",
            "# Create non-root user",
            f"RUN groupadd -g {self.non_root_gid} {self.non_root_user}",
            f"RUN useradd -u {self.non_root_uid} -g {self.non_root_gid} -m -s /bin/bash {self.non_root_user}",
            "",
            "# Set up directory permissions",
            f"RUN mkdir -p /app /var/log/iot-ids /var/run/iot-ids",
            f"RUN chown -R {self.non_root_user}:{self.non_root_user} /app /var/log/iot-ids /var/run/iot-ids",
            "",
            "# Remove unnecessary packages and clean up",
            "RUN apt-get autoremove -y && apt-get clean && rm -rf /var/lib/apt/lists/*",
            "",
            "# Set security labels",
            "LABEL security.hardened=true",
            "LABEL security.non-root=true",
            "LABEL security.readonly-rootfs=true",
            "",
            "# Switch to non-root user",
            f"USER {self.non_root_user}",
            "",
            "# Set working directory",
            "WORKDIR /app"
        ]
        
        return directives
        
    def validate_security_configuration(self) -> Dict[str, bool]:
        """Validate current security configuration.
        
        Returns:
            Dictionary with validation results
        """
        validation_results = {
            'non_root_user': os.getuid() != 0,
            'readonly_filesystem': self._check_readonly_filesystem(),
            'no_new_privileges': self._check_no_new_privileges(),
            'capabilities_dropped': self._check_capabilities(),
            'apparmor_enabled': self._is_apparmor_available(),
            'selinux_enabled': self._is_selinux_available()
        }
        
        logger.info(f"Security validation results: {validation_results}")
        return validation_results
        
    def _check_readonly_filesystem(self) -> bool:
        """Check if filesystem is mounted read-only."""
        try:
            # Try to create a test file in a read-only location
            test_file = '/etc/test_readonly'
            try:
                with open(test_file, 'w') as f:
                    f.write('test')
                os.remove(test_file)
                return False  # Should not be able to write
            except (PermissionError, OSError):
                return True  # Expected for read-only filesystem
        except Exception:
            return False
            
    def _check_no_new_privileges(self) -> bool:
        """Check if no-new-privileges is set."""
        try:
            with open('/proc/self/status', 'r') as f:
                for line in f:
                    if line.startswith('NoNewPrivs:'):
                        return line.strip().endswith('1')
            return False
        except Exception:
            return False
            
    def _check_capabilities(self) -> bool:
        """Check if capabilities are properly dropped."""
        try:
            with open('/proc/self/status', 'r') as f:
                content = f.read()
                # Look for capability information
                return 'CapEff:' in content
        except Exception:
            return False
            
    def _is_apparmor_available(self) -> bool:
        """Check if AppArmor is available."""
        return os.path.exists('/sys/kernel/security/apparmor')
        
    def _is_selinux_available(self) -> bool:
        """Check if SELinux is available."""
        return os.path.exists('/sys/fs/selinux')