"""Network security and segmentation management."""

import os
import logging
import subprocess
import ipaddress
from typing import Dict, List, Optional, Any, Union
from pathlib import Path
import json

logger = logging.getLogger(__name__)


class VLANManager:
    """Manages VLAN configuration for network segmentation."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize VLAN manager.
        
        Args:
            config: VLAN configuration dictionary
        """
        self.config = config or {}
        self.vlan_configs = self.config.get('vlans', {})
        self.interface_prefix = self.config.get('interface_prefix', 'eth0')
        
    def create_vlan_interface(self, vlan_id: int, ip_address: str, netmask: str) -> bool:
        """Create a VLAN interface.
        
        Args:
            vlan_id: VLAN ID (1-4094)
            ip_address: IP address for the VLAN interface
            netmask: Network mask for the VLAN
            
        Returns:
            True if VLAN interface was created successfully
        """
        try:
            if not (1 <= vlan_id <= 4094):
                raise ValueError(f"Invalid VLAN ID: {vlan_id}. Must be between 1 and 4094")
                
            # Validate IP address and netmask
            network = ipaddress.IPv4Network(f"{ip_address}/{netmask}", strict=False)
            
            interface_name = f"{self.interface_prefix}.{vlan_id}"
            
            # Create VLAN interface using ip command
            commands = [
                ['ip', 'link', 'add', 'link', self.interface_prefix, 'name', interface_name, 'type', 'vlan', 'id', str(vlan_id)],
                ['ip', 'addr', 'add', f"{ip_address}/{netmask}", 'dev', interface_name],
                ['ip', 'link', 'set', 'dev', interface_name, 'up']
            ]
            
            for cmd in commands:
                result = subprocess.run(cmd, capture_output=True, text=True, check=True)
                
            logger.info(f"Created VLAN interface {interface_name} with IP {ip_address}/{netmask}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to create VLAN interface {vlan_id}: {e}")
            return False
            
    def delete_vlan_interface(self, vlan_id: int) -> bool:
        """Delete a VLAN interface.
        
        Args:
            vlan_id: VLAN ID to delete
            
        Returns:
            True if VLAN interface was deleted successfully
        """
        try:
            interface_name = f"{self.interface_prefix}.{vlan_id}"
            
            # Delete VLAN interface
            result = subprocess.run([
                'ip', 'link', 'delete', interface_name
            ], capture_output=True, text=True, check=True)
            
            logger.info(f"Deleted VLAN interface {interface_name}")
            return True
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to delete VLAN interface {vlan_id}: {e}")
            return False
            
    def configure_device_class_vlans(self) -> bool:
        """Configure VLANs for different device classes.
        
        Returns:
            True if all VLANs were configured successfully
        """
        device_class_vlans = {
            'cameras': {'vlan_id': 10, 'network': '192.168.10.0/24'},
            'sensors': {'vlan_id': 20, 'network': '192.168.20.0/24'},
            'smart_plugs': {'vlan_id': 30, 'network': '192.168.30.0/24'},
            'thermostats': {'vlan_id': 40, 'network': '192.168.40.0/24'},
            'hubs': {'vlan_id': 50, 'network': '192.168.50.0/24'},
            'management': {'vlan_id': 100, 'network': '192.168.100.0/24'}
        }
        
        success = True
        for device_class, config in device_class_vlans.items():
            try:
                network = ipaddress.IPv4Network(config['network'])
                gateway_ip = str(network.network_address + 1)
                netmask = str(network.prefixlen)
                
                if not self.create_vlan_interface(config['vlan_id'], gateway_ip, netmask):
                    success = False
                    
            except Exception as e:
                logger.error(f"Failed to configure VLAN for {device_class}: {e}")
                success = False
                
        return success
        
    def get_vlan_interfaces(self) -> List[Dict[str, Any]]:
        """Get list of configured VLAN interfaces.
        
        Returns:
            List of VLAN interface information
        """
        interfaces = []
        
        try:
            result = subprocess.run([
                'ip', '-j', 'link', 'show', 'type', 'vlan'
            ], capture_output=True, text=True, check=True)
            
            vlan_data = json.loads(result.stdout)
            
            for interface in vlan_data:
                if 'linkinfo' in interface and interface['linkinfo'].get('info_kind') == 'vlan':
                    vlan_info = interface['linkinfo']['info_data']
                    interfaces.append({
                        'name': interface['ifname'],
                        'vlan_id': vlan_info.get('id'),
                        'parent': vlan_info.get('link'),
                        'state': interface.get('operstate', 'unknown')
                    })
                    
        except Exception as e:
            logger.error(f"Failed to get VLAN interfaces: {e}")
            
        return interfaces


class EgressPolicyManager:
    """Manages deny-by-default egress policies using iptables."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize egress policy manager.
        
        Args:
            config: Egress policy configuration
        """
        self.config = config or {}
        self.chain_name = self.config.get('chain_name', 'IOT_EGRESS')
        self.allowed_destinations = self.config.get('allowed_destinations', [])
        
    def setup_deny_by_default_policy(self) -> bool:
        """Set up deny-by-default egress policy.
        
        Returns:
            True if policy was set up successfully
        """
        try:
            # Create custom chain for IoT egress rules
            self._create_custom_chain()
            
            # Add jump rule to custom chain
            self._add_jump_rule()
            
            # Add allowed destination rules
            for destination in self.allowed_destinations:
                self._add_allowed_destination(destination)
                
            # Add default deny rule
            self._add_default_deny_rule()
            
            logger.info("Set up deny-by-default egress policy")
            return True
            
        except Exception as e:
            logger.error(f"Failed to set up egress policy: {e}")
            return False
            
    def add_allowed_destination(self, destination: str, port: Optional[int] = None, 
                              protocol: str = 'tcp') -> bool:
        """Add an allowed egress destination.
        
        Args:
            destination: IP address or CIDR block
            port: Destination port (optional)
            protocol: Protocol (tcp/udp/icmp)
            
        Returns:
            True if rule was added successfully
        """
        try:
            # Validate destination
            ipaddress.ip_network(destination, strict=False)
            
            rule_parts = [
                'iptables', '-A', self.chain_name,
                '-p', protocol,
                '-d', destination
            ]
            
            if port:
                rule_parts.extend(['--dport', str(port)])
                
            rule_parts.extend(['-j', 'ACCEPT'])
            
            result = subprocess.run(rule_parts, capture_output=True, text=True, check=True)
            
            logger.info(f"Added allowed egress destination: {destination}:{port or 'any'}/{protocol}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to add allowed destination {destination}: {e}")
            return False
            
    def remove_allowed_destination(self, destination: str, port: Optional[int] = None,
                                 protocol: str = 'tcp') -> bool:
        """Remove an allowed egress destination.
        
        Args:
            destination: IP address or CIDR block
            port: Destination port (optional)
            protocol: Protocol (tcp/udp/icmp)
            
        Returns:
            True if rule was removed successfully
        """
        try:
            rule_parts = [
                'iptables', '-D', self.chain_name,
                '-p', protocol,
                '-d', destination
            ]
            
            if port:
                rule_parts.extend(['--dport', str(port)])
                
            rule_parts.extend(['-j', 'ACCEPT'])
            
            result = subprocess.run(rule_parts, capture_output=True, text=True, check=True)
            
            logger.info(f"Removed allowed egress destination: {destination}:{port or 'any'}/{protocol}")
            return True
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to remove allowed destination {destination}: {e}")
            return False
            
    def get_egress_rules(self) -> List[Dict[str, Any]]:
        """Get current egress rules.
        
        Returns:
            List of egress rule information
        """
        rules = []
        
        try:
            result = subprocess.run([
                'iptables', '-L', self.chain_name, '-n', '--line-numbers'
            ], capture_output=True, text=True, check=True)
            
            lines = result.stdout.split('\n')[2:]  # Skip header lines
            
            for line in lines:
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 4:
                        rules.append({
                            'line_number': parts[0],
                            'target': parts[1],
                            'protocol': parts[2],
                            'source': parts[3],
                            'destination': parts[4] if len(parts) > 4 else 'anywhere'
                        })
                        
        except Exception as e:
            logger.error(f"Failed to get egress rules: {e}")
            
        return rules
        
    def clear_egress_rules(self) -> bool:
        """Clear all egress rules.
        
        Returns:
            True if rules were cleared successfully
        """
        try:
            # Flush custom chain
            subprocess.run([
                'iptables', '-F', self.chain_name
            ], capture_output=True, text=True, check=True)
            
            # Remove jump rule
            subprocess.run([
                'iptables', '-D', 'OUTPUT', '-j', self.chain_name
            ], capture_output=True, text=True)
            
            # Delete custom chain
            subprocess.run([
                'iptables', '-X', self.chain_name
            ], capture_output=True, text=True)
            
            logger.info("Cleared all egress rules")
            return True
            
        except Exception as e:
            logger.error(f"Failed to clear egress rules: {e}")
            return False
            
    def _create_custom_chain(self) -> None:
        """Create custom iptables chain for IoT egress rules."""
        try:
            # Try to create chain (will fail if it already exists)
            subprocess.run([
                'iptables', '-N', self.chain_name
            ], capture_output=True, text=True, check=True)
        except subprocess.CalledProcessError:
            # Chain already exists, flush it
            subprocess.run([
                'iptables', '-F', self.chain_name
            ], capture_output=True, text=True)
            
    def _add_jump_rule(self) -> None:
        """Add jump rule to custom chain."""
        try:
            # Remove existing jump rule if present
            subprocess.run([
                'iptables', '-D', 'OUTPUT', '-j', self.chain_name
            ], capture_output=True, text=True)
        except subprocess.CalledProcessError:
            pass  # Rule doesn't exist
            
        # Add jump rule
        subprocess.run([
            'iptables', '-I', 'OUTPUT', '1', '-j', self.chain_name
        ], capture_output=True, text=True, check=True)
        
    def _add_allowed_destination(self, destination: Dict[str, Any]) -> None:
        """Add an allowed destination rule."""
        self.add_allowed_destination(
            destination.get('address'),
            destination.get('port'),
            destination.get('protocol', 'tcp')
        )
        
    def _add_default_deny_rule(self) -> None:
        """Add default deny rule at the end of the chain."""
        subprocess.run([
            'iptables', '-A', self.chain_name, '-j', 'DROP'
        ], capture_output=True, text=True, check=True)


class NetworkAccessControlValidator:
    """Validates network access control configurations."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize network access control validator.
        
        Args:
            config: Validation configuration
        """
        self.config = config or {}
        
    def validate_vlan_configuration(self, vlan_manager: VLANManager) -> Dict[str, Any]:
        """Validate VLAN configuration.
        
        Args:
            vlan_manager: VLAN manager instance
            
        Returns:
            Validation results dictionary
        """
        results = {
            'valid': True,
            'errors': [],
            'warnings': [],
            'vlan_interfaces': []
        }
        
        try:
            # Get VLAN interfaces
            interfaces = vlan_manager.get_vlan_interfaces()
            results['vlan_interfaces'] = interfaces
            
            # Check if VLANs are properly configured
            expected_vlans = [10, 20, 30, 40, 50, 100]  # Device class VLANs
            configured_vlans = [iface['vlan_id'] for iface in interfaces]
            
            for vlan_id in expected_vlans:
                if vlan_id not in configured_vlans:
                    results['warnings'].append(f"Expected VLAN {vlan_id} not configured")
                    
            # Check for VLAN ID conflicts
            if len(configured_vlans) != len(set(configured_vlans)):
                results['errors'].append("Duplicate VLAN IDs detected")
                results['valid'] = False
                
        except Exception as e:
            results['errors'].append(f"VLAN validation error: {e}")
            results['valid'] = False
            
        return results
        
    def validate_egress_policy(self, policy_manager: EgressPolicyManager) -> Dict[str, Any]:
        """Validate egress policy configuration.
        
        Args:
            policy_manager: Egress policy manager instance
            
        Returns:
            Validation results dictionary
        """
        results = {
            'valid': True,
            'errors': [],
            'warnings': [],
            'rules': []
        }
        
        try:
            # Get egress rules
            rules = policy_manager.get_egress_rules()
            results['rules'] = rules
            
            # Check if default deny rule exists
            has_default_deny = any(rule['target'] == 'DROP' for rule in rules)
            if not has_default_deny:
                results['errors'].append("No default deny rule found")
                results['valid'] = False
                
            # Check for overly permissive rules
            for rule in rules:
                if rule['destination'] == '0.0.0.0/0' and rule['target'] == 'ACCEPT':
                    results['warnings'].append("Overly permissive rule allowing all destinations")
                    
        except Exception as e:
            results['errors'].append(f"Egress policy validation error: {e}")
            results['valid'] = False
            
        return results
        
    def validate_network_segmentation(self) -> Dict[str, Any]:
        """Validate overall network segmentation.
        
        Returns:
            Validation results dictionary
        """
        results = {
            'valid': True,
            'errors': [],
            'warnings': [],
            'segmentation_score': 0.0
        }
        
        try:
            # Check if iptables is available
            result = subprocess.run([
                'iptables', '--version'
            ], capture_output=True, text=True)
            
            if result.returncode != 0:
                results['errors'].append("iptables not available")
                results['valid'] = False
                return results
                
            # Check if VLAN support is available
            result = subprocess.run([
                'modprobe', '8021q'
            ], capture_output=True, text=True)
            
            if result.returncode != 0:
                results['warnings'].append("VLAN kernel module may not be available")
                
            # Calculate segmentation score based on various factors
            score = 0.0
            
            # Check for network namespaces
            result = subprocess.run([
                'ip', 'netns', 'list'
            ], capture_output=True, text=True)
            
            if result.returncode == 0:
                score += 0.2  # Network namespaces available
                
            # Check for bridge interfaces
            result = subprocess.run([
                'brctl', 'show'
            ], capture_output=True, text=True)
            
            if result.returncode == 0:
                score += 0.2  # Bridge utilities available
                
            # Check for advanced routing
            result = subprocess.run([
                'ip', 'route', 'show', 'table', 'all'
            ], capture_output=True, text=True)
            
            if result.returncode == 0 and 'table' in result.stdout:
                score += 0.2  # Advanced routing available
                
            # Check for traffic control
            result = subprocess.run([
                'tc', 'qdisc', 'show'
            ], capture_output=True, text=True)
            
            if result.returncode == 0:
                score += 0.2  # Traffic control available
                
            # Check for netfilter modules
            if os.path.exists('/proc/net/netfilter'):
                score += 0.2  # Netfilter available
                
            results['segmentation_score'] = score
            
            if score < 0.5:
                results['warnings'].append("Limited network segmentation capabilities")
                
        except Exception as e:
            results['errors'].append(f"Network segmentation validation error: {e}")
            results['valid'] = False
            
        return results