"""ARM-optimized deployment configurations and utilities."""

import os
import logging
import platform
import subprocess
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path
import json

logger = logging.getLogger(__name__)


class ARMOptimizer:
    """ARM architecture optimization utilities."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize ARM optimizer.
        
        Args:
            config: ARM optimization configuration
        """
        self.config = config or {}
        self.architecture = platform.machine().lower()
        self.is_arm = self.architecture in ['arm', 'armv7l', 'aarch64', 'arm64']
        self.cpu_info = self._get_cpu_info()
        
    def detect_arm_capabilities(self) -> Dict[str, Any]:
        """Detect ARM-specific capabilities and features.
        
        Returns:
            Dictionary with ARM capability information
        """
        capabilities = {
            'is_arm': self.is_arm,
            'architecture': self.architecture,
            'cpu_cores': os.cpu_count(),
            'features': [],
            'optimization_flags': [],
            'docker_platform': self._get_docker_platform()
        }
        
        if not self.is_arm:
            return capabilities
            
        try:
            # Check for NEON support (ARM SIMD)
            if self._has_neon_support():
                capabilities['features'].append('neon')
                capabilities['optimization_flags'].extend(['-mfpu=neon', '-ftree-vectorize'])
                
            # Check for hardware floating point
            if self._has_hard_float():
                capabilities['features'].append('hard_float')
                capabilities['optimization_flags'].append('-mfloat-abi=hard')
                
            # Check for Thumb instruction set
            if self._has_thumb_support():
                capabilities['features'].append('thumb')
                capabilities['optimization_flags'].append('-mthumb')
                
            # ARM64 specific optimizations
            if self.architecture in ['aarch64', 'arm64']:
                capabilities['features'].append('aarch64')
                capabilities['optimization_flags'].extend(['-march=armv8-a', '-mtune=cortex-a72'])
                
            # Raspberry Pi specific optimizations
            if self._is_raspberry_pi():
                capabilities['features'].append('raspberry_pi')
                pi_model = self._get_raspberry_pi_model()
                capabilities['pi_model'] = pi_model
                capabilities['optimization_flags'].extend(self._get_pi_optimization_flags(pi_model))
                
        except Exception as e:
            logger.error(f"Error detecting ARM capabilities: {e}")
            
        return capabilities
        
    def generate_dockerfile_optimizations(self) -> List[str]:
        """Generate Dockerfile directives for ARM optimization.
        
        Returns:
            List of Dockerfile directives
        """
        directives = []
        
        if not self.is_arm:
            directives.append("# No ARM-specific optimizations needed")
            return directives
            
        capabilities = self.detect_arm_capabilities()
        
        directives.extend([
            "# ARM-specific optimizations",
            f"# Architecture: {self.architecture}",
            ""
        ])
        
        # Base image selection
        if self.architecture in ['aarch64', 'arm64']:
            directives.extend([
                "# Use ARM64 base image",
                "FROM --platform=linux/arm64 python:3.11-slim-bullseye",
                ""
            ])
        elif self.architecture in ['arm', 'armv7l']:
            directives.extend([
                "# Use ARM32 base image", 
                "FROM --platform=linux/arm/v7 python:3.11-slim-bullseye",
                ""
            ])
            
        # Install ARM-optimized packages
        directives.extend([
            "# Install ARM-optimized packages",
            "RUN apt-get update && apt-get install -y \\",
            "    gcc-arm-linux-gnueabihf \\",
            "    libblas3 \\",
            "    liblapack3 \\",
            "    libatlas-base-dev \\",
            "    gfortran \\",
            "    && rm -rf /var/lib/apt/lists/*",
            ""
        ])
        
        # Python package optimizations
        if 'neon' in capabilities['features']:
            directives.extend([
                "# Enable NEON optimizations for NumPy/SciPy",
                "ENV NPY_NUM_BUILD_JOBS=4",
                "ENV ATLAS=None",
                "ENV BLAS=/usr/lib/arm-linux-gnueabihf/libblas.so.3",
                "ENV LAPACK=/usr/lib/arm-linux-gnueabihf/liblapack.so.3",
                ""
            ])
            
        # Memory optimizations for ARM devices
        directives.extend([
            "# Memory optimizations for ARM devices",
            "ENV PYTHONUNBUFFERED=1",
            "ENV PYTHONDONTWRITEBYTECODE=1",
            "ENV PIP_NO_CACHE_DIR=1",
            ""
        ])
        
        # Raspberry Pi specific optimizations
        if 'raspberry_pi' in capabilities['features']:
            directives.extend([
                "# Raspberry Pi specific optimizations",
                "ENV GPU_MEM=16",  # Minimal GPU memory for headless operation
                "ENV ARM_FREQ=1500",  # Conservative CPU frequency
                ""
            ])
            
        return directives
        
    def generate_docker_compose_config(self) -> Dict[str, Any]:
        """Generate Docker Compose configuration for ARM deployment.
        
        Returns:
            Docker Compose configuration dictionary
        """
        config = {
            'version': '3.8',
            'services': {}
        }
        
        capabilities = self.detect_arm_capabilities()
        
        # Base service configuration
        base_service = {
            'platform': capabilities['docker_platform'],
            'restart': 'unless-stopped',
            'deploy': {
                'resources': {
                    'limits': {
                        'cpus': str(min(capabilities['cpu_cores'], 2)),  # Limit CPU usage
                        'memory': '512M'  # Conservative memory limit
                    }
                }
            }
        }
        
        # Edge gateway service
        edge_service = base_service.copy()
        edge_service.update({
            'image': 'iot-ids/edge-gateway:arm64' if self.architecture in ['aarch64', 'arm64'] else 'iot-ids/edge-gateway:armv7',
            'privileged': True,  # Required for packet capture
            'network_mode': 'host',
            'volumes': [
                '/var/log/iot-ids:/var/log/iot-ids',
                '/etc/iot-ids:/etc/iot-ids:ro'
            ],
            'environment': [
                'ARM_OPTIMIZED=true',
                f'CPU_CORES={capabilities["cpu_cores"]}',
                'MEMORY_LIMIT=256M'
            ]
        })
        
        # AI inference service
        ai_service = base_service.copy()
        ai_service.update({
            'image': 'iot-ids/ai-inference:arm64' if self.architecture in ['aarch64', 'arm64'] else 'iot-ids/ai-inference:armv7',
            'ports': ['8080:8080'],
            'volumes': [
                '/models:/models:ro',
                '/var/log/iot-ids:/var/log/iot-ids'
            ],
            'environment': [
                'ARM_OPTIMIZED=true',
                'OPENBLAS_NUM_THREADS=2',  # Limit BLAS threads
                'OMP_NUM_THREADS=2'  # Limit OpenMP threads
            ]
        })
        
        config['services'] = {
            'edge-gateway': edge_service,
            'ai-inference': ai_service
        }
        
        return config
        
    def optimize_python_packages(self) -> Dict[str, str]:
        """Get ARM-optimized Python package installation commands.
        
        Returns:
            Dictionary with package optimization commands
        """
        optimizations = {}
        
        if not self.is_arm:
            return optimizations
            
        # NumPy optimization for ARM
        optimizations['numpy'] = (
            "pip install --no-binary numpy numpy && "
            "pip install --no-binary scipy scipy"
        )
        
        # TensorFlow Lite for ARM
        if self.architecture in ['aarch64', 'arm64']:
            optimizations['tensorflow'] = "pip install tensorflow-aarch64"
        else:
            optimizations['tensorflow'] = "pip install tflite-runtime"
            
        # PyTorch for ARM
        optimizations['pytorch'] = (
            "pip install torch torchvision torchaudio "
            "--index-url https://download.pytorch.org/whl/cpu"
        )
        
        # Scikit-learn with ARM optimizations
        optimizations['scikit-learn'] = (
            "pip install --no-binary scikit-learn scikit-learn"
        )
        
        return optimizations
        
    def get_performance_tuning_config(self) -> Dict[str, Any]:
        """Get performance tuning configuration for ARM devices.
        
        Returns:
            Performance tuning configuration
        """
        config = {
            'cpu': {
                'governor': 'performance',
                'max_freq': self._get_max_cpu_frequency(),
                'scaling_available': self._get_available_cpu_governors()
            },
            'memory': {
                'swappiness': 10,  # Reduce swap usage
                'dirty_ratio': 5,  # Reduce dirty page ratio
                'dirty_background_ratio': 2
            },
            'network': {
                'tcp_congestion_control': 'bbr',
                'tcp_window_scaling': 1,
                'tcp_timestamps': 1
            },
            'io': {
                'scheduler': 'deadline',  # Better for ARM storage
                'read_ahead_kb': 128
            }
        }
        
        return config
        
    def apply_performance_tuning(self) -> bool:
        """Apply performance tuning settings.
        
        Returns:
            True if tuning was applied successfully
        """
        try:
            config = self.get_performance_tuning_config()
            
            # Apply CPU governor settings
            if self._set_cpu_governor(config['cpu']['governor']):
                logger.info(f"Set CPU governor to {config['cpu']['governor']}")
                
            # Apply memory settings
            sysctl_settings = {
                'vm.swappiness': config['memory']['swappiness'],
                'vm.dirty_ratio': config['memory']['dirty_ratio'],
                'vm.dirty_background_ratio': config['memory']['dirty_background_ratio']
            }
            
            for setting, value in sysctl_settings.items():
                if self._set_sysctl_value(setting, value):
                    logger.info(f"Set {setting} to {value}")
                    
            return True
            
        except Exception as e:
            logger.error(f"Failed to apply performance tuning: {e}")
            return False
            
    def _get_cpu_info(self) -> Dict[str, Any]:
        """Get CPU information."""
        cpu_info = {}
        
        try:
            # Try Linux-style /proc/cpuinfo first
            if os.path.exists('/proc/cpuinfo'):
                with open('/proc/cpuinfo', 'r') as f:
                    for line in f:
                        if ':' in line:
                            key, value = line.split(':', 1)
                            cpu_info[key.strip()] = value.strip()
            else:
                # Fallback for non-Linux systems
                cpu_info['processor'] = platform.processor()
                cpu_info['machine'] = platform.machine()
                cpu_info['system'] = platform.system()
        except Exception:
            pass
            
        return cpu_info
        
    def _has_neon_support(self) -> bool:
        """Check if CPU supports NEON instructions."""
        return 'neon' in self.cpu_info.get('Features', '').lower()
        
    def _has_hard_float(self) -> bool:
        """Check if CPU supports hardware floating point."""
        return 'vfp' in self.cpu_info.get('Features', '').lower()
        
    def _has_thumb_support(self) -> bool:
        """Check if CPU supports Thumb instruction set."""
        return 'thumb' in self.cpu_info.get('Features', '').lower()
        
    def _is_raspberry_pi(self) -> bool:
        """Check if running on Raspberry Pi."""
        try:
            # Try Linux-specific check first
            if os.path.exists('/proc/device-tree/model'):
                with open('/proc/device-tree/model', 'r') as f:
                    model = f.read().lower()
                    return 'raspberry pi' in model
            else:
                # Fallback: not a Raspberry Pi if not on Linux
                return False
        except Exception:
            return False
            
    def _get_raspberry_pi_model(self) -> Optional[str]:
        """Get Raspberry Pi model information."""
        try:
            if os.path.exists('/proc/device-tree/model'):
                with open('/proc/device-tree/model', 'r') as f:
                    return f.read().strip()
        except Exception:
            pass
        return None
            
    def _get_pi_optimization_flags(self, model: str) -> List[str]:
        """Get optimization flags for specific Raspberry Pi model."""
        flags = []
        
        if not model:
            return flags
            
        model_lower = model.lower()
        
        if 'pi 4' in model_lower:
            flags.extend(['-mcpu=cortex-a72', '-mtune=cortex-a72'])
        elif 'pi 3' in model_lower:
            flags.extend(['-mcpu=cortex-a53', '-mtune=cortex-a53'])
        elif 'pi 2' in model_lower:
            flags.extend(['-mcpu=cortex-a7', '-mtune=cortex-a7'])
            
        return flags
        
    def _get_docker_platform(self) -> str:
        """Get Docker platform string for current architecture."""
        if self.architecture in ['aarch64', 'arm64']:
            return 'linux/arm64'
        elif self.architecture in ['arm', 'armv7l']:
            return 'linux/arm/v7'
        else:
            return 'linux/amd64'
            
    def _get_max_cpu_frequency(self) -> Optional[int]:
        """Get maximum CPU frequency."""
        try:
            if os.path.exists('/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq'):
                with open('/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq', 'r') as f:
                    return int(f.read().strip())
        except Exception:
            pass
        return None
            
    def _get_available_cpu_governors(self) -> List[str]:
        """Get available CPU governors."""
        try:
            if os.path.exists('/sys/devices/system/cpu/cpu0/cpufreq/scaling_available_governors'):
                with open('/sys/devices/system/cpu/cpu0/cpufreq/scaling_available_governors', 'r') as f:
                    return f.read().strip().split()
        except Exception:
            pass
        return []
            
    def _set_cpu_governor(self, governor: str) -> bool:
        """Set CPU governor."""
        try:
            for cpu_dir in Path('/sys/devices/system/cpu').glob('cpu[0-9]*'):
                governor_file = cpu_dir / 'cpufreq' / 'scaling_governor'
                if governor_file.exists():
                    with open(governor_file, 'w') as f:
                        f.write(governor)
            return True
        except Exception as e:
            logger.error(f"Failed to set CPU governor: {e}")
            return False
            
    def _set_sysctl_value(self, setting: str, value: Any) -> bool:
        """Set sysctl value."""
        try:
            result = subprocess.run([
                'sysctl', '-w', f'{setting}={value}'
            ], capture_output=True, text=True, check=True)
            return True
        except Exception as e:
            logger.error(f"Failed to set sysctl value {setting}: {e}")
            return False