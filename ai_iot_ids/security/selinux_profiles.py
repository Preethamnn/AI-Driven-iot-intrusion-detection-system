"""SELinux profile management for IoT IDS."""

import os
import logging
import subprocess
from typing import Dict, List, Optional, Any
from pathlib import Path

logger = logging.getLogger(__name__)


class SELinuxProfileManager:
    """Manages SELinux profiles and policies for IoT IDS components."""
    
    def __init__(self, policy_dir: str = "/etc/selinux/local"):
        """Initialize SELinux profile manager.
        
        Args:
            policy_dir: Directory for custom SELinux policies
        """
        self.policy_dir = Path(policy_dir)
        self.module_name = "iot_ids"
        
    def create_edge_gateway_policy(self) -> str:
        """Create SELinux policy for edge gateway component.
        
        Returns:
            SELinux policy content as string
        """
        policy_content = f"""policy_module({self.module_name}_edge, 1.0)

########################################
#
# Declarations
#

type iot_ids_edge_t;
type iot_ids_edge_exec_t;
domain_type(iot_ids_edge_t)
init_daemon_domain(iot_ids_edge_t, iot_ids_edge_exec_t)

type iot_ids_edge_var_run_t;
files_pid_file(iot_ids_edge_var_run_t)

type iot_ids_edge_var_log_t;
logging_log_file(iot_ids_edge_var_log_t)

type iot_ids_edge_tmp_t;
files_tmp_file(iot_ids_edge_tmp_t)

########################################
#
# iot_ids_edge local policy
#

allow iot_ids_edge_t self:capability {{ net_raw net_admin dac_override }};
allow iot_ids_edge_t self:process {{ fork signal_perms }};
allow iot_ids_edge_t self:fifo_file rw_fifo_file_perms;
allow iot_ids_edge_t self:unix_stream_socket create_stream_socket_perms;

# Network access for packet capture
allow iot_ids_edge_t self:packet_socket create_socket_perms;
allow iot_ids_edge_t self:netlink_route_socket create_netlink_socket_perms;
allow iot_ids_edge_t self:tcp_socket create_stream_socket_perms;
allow iot_ids_edge_t self:udp_socket create_socket_perms;

# File access
manage_dirs_pattern(iot_ids_edge_t, iot_ids_edge_var_run_t, iot_ids_edge_var_run_t)
manage_files_pattern(iot_ids_edge_t, iot_ids_edge_var_run_t, iot_ids_edge_var_run_t)
files_pid_filetrans(iot_ids_edge_t, iot_ids_edge_var_run_t, {{ file dir }})

manage_dirs_pattern(iot_ids_edge_t, iot_ids_edge_var_log_t, iot_ids_edge_var_log_t)
manage_files_pattern(iot_ids_edge_t, iot_ids_edge_var_log_t, iot_ids_edge_var_log_t)
logging_log_filetrans(iot_ids_edge_t, iot_ids_edge_var_log_t, {{ file dir }})

manage_dirs_pattern(iot_ids_edge_t, iot_ids_edge_tmp_t, iot_ids_edge_tmp_t)
manage_files_pattern(iot_ids_edge_t, iot_ids_edge_tmp_t, iot_ids_edge_tmp_t)
files_tmp_filetrans(iot_ids_edge_t, iot_ids_edge_tmp_t, {{ file dir }})

# System access
kernel_read_network_state(iot_ids_edge_t)
kernel_read_system_state(iot_ids_edge_t)
dev_read_sysfs(iot_ids_edge_t)
dev_read_urand(iot_ids_edge_t)

# Python interpreter access
corecmd_exec_bin(iot_ids_edge_t)
libs_exec_lib_files(iot_ids_edge_t)

# Network communication
corenet_all_recvfrom_unlabeled(iot_ids_edge_t)
corenet_all_recvfrom_netlabel(iot_ids_edge_t)
corenet_tcp_sendrecv_generic_if(iot_ids_edge_t)
corenet_udp_sendrecv_generic_if(iot_ids_edge_t)
corenet_tcp_sendrecv_generic_node(iot_ids_edge_t)
corenet_udp_sendrecv_generic_node(iot_ids_edge_t)
corenet_tcp_connect_http_port(iot_ids_edge_t)
corenet_tcp_connect_https_port(iot_ids_edge_t)

# DNS resolution
sysnet_dns_name_resolve(iot_ids_edge_t)

# Logging
logging_send_syslog_msg(iot_ids_edge_t)

# Deny dangerous operations
neverallow iot_ids_edge_t self:capability {{ sys_admin sys_module }};
neverallow iot_ids_edge_t kernel_t:system module_load;
"""
        
        return policy_content
        
    def create_ai_service_policy(self) -> str:
        """Create SELinux policy for AI inference service.
        
        Returns:
            SELinux policy content as string
        """
        policy_content = f"""policy_module({self.module_name}_ai, 1.0)

########################################
#
# Declarations
#

type iot_ids_ai_t;
type iot_ids_ai_exec_t;
domain_type(iot_ids_ai_t)
init_daemon_domain(iot_ids_ai_t, iot_ids_ai_exec_t)

type iot_ids_ai_var_run_t;
files_pid_file(iot_ids_ai_var_run_t)

type iot_ids_ai_var_log_t;
logging_log_file(iot_ids_ai_var_log_t)

type iot_ids_ai_tmp_t;
files_tmp_file(iot_ids_ai_tmp_t)

type iot_ids_ai_models_t;
files_type(iot_ids_ai_models_t)

########################################
#
# iot_ids_ai local policy
#

allow iot_ids_ai_t self:process {{ fork signal_perms }};
allow iot_ids_ai_t self:fifo_file rw_fifo_file_perms;
allow iot_ids_ai_t self:unix_stream_socket create_stream_socket_perms;

# Network access for API endpoints
allow iot_ids_ai_t self:tcp_socket create_stream_socket_perms;
allow iot_ids_ai_t self:udp_socket create_socket_perms;

# File access
manage_dirs_pattern(iot_ids_ai_t, iot_ids_ai_var_run_t, iot_ids_ai_var_run_t)
manage_files_pattern(iot_ids_ai_t, iot_ids_ai_var_run_t, iot_ids_ai_var_run_t)
files_pid_filetrans(iot_ids_ai_t, iot_ids_ai_var_run_t, {{ file dir }})

manage_dirs_pattern(iot_ids_ai_t, iot_ids_ai_var_log_t, iot_ids_ai_var_log_t)
manage_files_pattern(iot_ids_ai_t, iot_ids_ai_var_log_t, iot_ids_ai_var_log_t)
logging_log_filetrans(iot_ids_ai_t, iot_ids_ai_var_log_t, {{ file dir }})

manage_dirs_pattern(iot_ids_ai_t, iot_ids_ai_tmp_t, iot_ids_ai_tmp_t)
manage_files_pattern(iot_ids_ai_t, iot_ids_ai_tmp_t, iot_ids_ai_tmp_t)
files_tmp_filetrans(iot_ids_ai_t, iot_ids_ai_tmp_t, {{ file dir }})

# Model files access
read_files_pattern(iot_ids_ai_t, iot_ids_ai_models_t, iot_ids_ai_models_t)
read_lnk_files_pattern(iot_ids_ai_t, iot_ids_ai_models_t, iot_ids_ai_models_t)

# System access
kernel_read_system_state(iot_ids_ai_t)
dev_read_sysfs(iot_ids_ai_t)
dev_read_urand(iot_ids_ai_t)

# Python interpreter access
corecmd_exec_bin(iot_ids_ai_t)
libs_exec_lib_files(iot_ids_ai_t)

# Network communication
corenet_all_recvfrom_unlabeled(iot_ids_ai_t)
corenet_all_recvfrom_netlabel(iot_ids_ai_t)
corenet_tcp_sendrecv_generic_if(iot_ids_ai_t)
corenet_tcp_sendrecv_generic_node(iot_ids_ai_t)
corenet_tcp_bind_generic_node(iot_ids_ai_t)
corenet_tcp_bind_http_port(iot_ids_ai_t)
corenet_tcp_connect_http_port(iot_ids_ai_t)
corenet_tcp_connect_https_port(iot_ids_ai_t)

# DNS resolution
sysnet_dns_name_resolve(iot_ids_ai_t)

# Logging
logging_send_syslog_msg(iot_ids_ai_t)

# GPU access for ML inference (if available)
optional_policy(`
    nvidia_exec_nvidia_gpu_t(iot_ids_ai_t)
    dev_rw_nvidia_dev(iot_ids_ai_t)
')

# Deny dangerous operations
neverallow iot_ids_ai_t self:capability {{ sys_admin sys_module }};
neverallow iot_ids_ai_t kernel_t:system module_load;
"""
        
        return policy_content
        
    def create_file_contexts(self) -> str:
        """Create SELinux file contexts configuration.
        
        Returns:
            File contexts content as string
        """
        contexts_content = f"""# IoT IDS SELinux file contexts

# Edge gateway
/usr/bin/iot-ids-edge		--	gen_context(system_u:object_r:iot_ids_edge_exec_t,s0)
/var/run/iot-ids-edge(/.*)?		gen_context(system_u:object_r:iot_ids_edge_var_run_t,s0)
/var/log/iot-ids-edge(/.*)?		gen_context(system_u:object_r:iot_ids_edge_var_log_t,s0)

# AI service
/usr/bin/iot-ids-ai		--	gen_context(system_u:object_r:iot_ids_ai_exec_t,s0)
/var/run/iot-ids-ai(/.*)?		gen_context(system_u:object_r:iot_ids_ai_var_run_t,s0)
/var/log/iot-ids-ai(/.*)?		gen_context(system_u:object_r:iot_ids_ai_var_log_t,s0)
/models(/.*)?				gen_context(system_u:object_r:iot_ids_ai_models_t,s0)
"""
        
        return contexts_content
        
    def install_policies(self) -> bool:
        """Install SELinux policies to the system.
        
        Returns:
            True if policies were installed successfully
        """
        try:
            if not self._is_selinux_available():
                logger.warning("SELinux is not available on this system")
                return False
                
            # Create policy directory if it doesn't exist
            self.policy_dir.mkdir(parents=True, exist_ok=True)
            
            # Create policy files
            edge_policy_path = self.policy_dir / f"{self.module_name}_edge.te"
            ai_policy_path = self.policy_dir / f"{self.module_name}_ai.te"
            contexts_path = self.policy_dir / f"{self.module_name}.fc"
            
            with open(edge_policy_path, 'w') as f:
                f.write(self.create_edge_gateway_policy())
                
            with open(ai_policy_path, 'w') as f:
                f.write(self.create_ai_service_policy())
                
            with open(contexts_path, 'w') as f:
                f.write(self.create_file_contexts())
                
            # Compile and install policies
            self._compile_and_install_policy(edge_policy_path)
            self._compile_and_install_policy(ai_policy_path)
            
            # Install file contexts
            self._install_file_contexts(contexts_path)
            
            logger.info("SELinux policies installed successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to install SELinux policies: {e}")
            return False
            
    def get_selinux_status(self) -> Dict[str, Any]:
        """Get SELinux status information.
        
        Returns:
            Dictionary with SELinux status information
        """
        status = {
            'enabled': False,
            'mode': 'unknown',
            'policy_version': 'unknown',
            'modules_loaded': []
        }
        
        try:
            if not self._is_selinux_available():
                return status
                
            # Get SELinux status
            result = subprocess.run([
                'sestatus'
            ], capture_output=True, text=True, check=True)
            
            for line in result.stdout.split('\n'):
                if 'SELinux status:' in line:
                    status['enabled'] = 'enabled' in line.lower()
                elif 'Current mode:' in line:
                    status['mode'] = line.split(':')[1].strip()
                elif 'Policy version:' in line:
                    status['policy_version'] = line.split(':')[1].strip()
                    
            # Get loaded modules
            result = subprocess.run([
                'semodule', '-l'
            ], capture_output=True, text=True)
            
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if self.module_name in line:
                        status['modules_loaded'].append(line.strip())
                        
        except Exception as e:
            logger.error(f"Failed to get SELinux status: {e}")
            
        return status
        
    def enable_module(self, module_name: str) -> bool:
        """Enable a SELinux module.
        
        Args:
            module_name: Name of the module to enable
            
        Returns:
            True if module was enabled successfully
        """
        try:
            result = subprocess.run([
                'semodule', '-e', module_name
            ], capture_output=True, text=True, check=True)
            
            logger.info(f"Enabled SELinux module: {module_name}")
            return True
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to enable SELinux module {module_name}: {e}")
            return False
            
    def disable_module(self, module_name: str) -> bool:
        """Disable a SELinux module.
        
        Args:
            module_name: Name of the module to disable
            
        Returns:
            True if module was disabled successfully
        """
        try:
            result = subprocess.run([
                'semodule', '-d', module_name
            ], capture_output=True, text=True, check=True)
            
            logger.info(f"Disabled SELinux module: {module_name}")
            return True
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to disable SELinux module {module_name}: {e}")
            return False
            
    def _is_selinux_available(self) -> bool:
        """Check if SELinux is available on the system."""
        return os.path.exists('/sys/fs/selinux')
        
    def _compile_and_install_policy(self, policy_path: Path) -> bool:
        """Compile and install a SELinux policy.
        
        Args:
            policy_path: Path to the policy file
            
        Returns:
            True if policy was compiled and installed successfully
        """
        try:
            # Compile policy
            result = subprocess.run([
                'checkmodule', '-M', '-m', '-o', 
                str(policy_path.with_suffix('.mod')), 
                str(policy_path)
            ], capture_output=True, text=True, check=True)
            
            # Create policy package
            result = subprocess.run([
                'semodule_package', '-o', 
                str(policy_path.with_suffix('.pp')), 
                '-m', str(policy_path.with_suffix('.mod'))
            ], capture_output=True, text=True, check=True)
            
            # Install policy
            result = subprocess.run([
                'semodule', '-i', str(policy_path.with_suffix('.pp'))
            ], capture_output=True, text=True, check=True)
            
            logger.info(f"Compiled and installed SELinux policy: {policy_path}")
            return True
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to compile/install SELinux policy {policy_path}: {e}")
            return False
            
    def _install_file_contexts(self, contexts_path: Path) -> bool:
        """Install SELinux file contexts.
        
        Args:
            contexts_path: Path to the file contexts file
            
        Returns:
            True if file contexts were installed successfully
        """
        try:
            # Install file contexts
            result = subprocess.run([
                'semanage', 'fcontext', '-a', '-f', str(contexts_path)
            ], capture_output=True, text=True, check=True)
            
            # Restore file contexts
            result = subprocess.run([
                'restorecon', '-R', '/usr/bin/', '/var/run/', '/var/log/', '/models/'
            ], capture_output=True, text=True)
            
            logger.info(f"Installed SELinux file contexts: {contexts_path}")
            return True
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to install SELinux file contexts {contexts_path}: {e}")
            return False