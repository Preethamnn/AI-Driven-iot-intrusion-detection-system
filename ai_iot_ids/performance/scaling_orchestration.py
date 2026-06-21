"""Horizontal scaling support with container orchestration."""

import logging
import time
import json
import subprocess
from typing import Dict, List, Optional, Any, Callable
from pathlib import Path
import requests
import threading

logger = logging.getLogger(__name__)


class HorizontalScaler:
    """Manages horizontal scaling of containerized services."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize horizontal scaler.
        
        Args:
            config: Scaling configuration
        """
        self.config = config or {}
        self.orchestrator = self.config.get('orchestrator', 'docker-compose')
        self.scaling_policies = self.config.get('scaling_policies', {})
        self.monitoring_interval = self.config.get('monitoring_interval', 30)
        self.cooldown_period = self.config.get('cooldown_period', 300)  # 5 minutes
        
        # Scaling state
        self.last_scaling_action = {}
        self.current_replicas = {}
        self.metrics_history = {}
        self._monitoring_thread = None
        self._stop_monitoring = threading.Event()
        
    def start_monitoring(self) -> None:
        """Start automatic scaling monitoring."""
        if self._monitoring_thread and self._monitoring_thread.is_alive():
            return
            
        self._stop_monitoring.clear()
        self._monitoring_thread = threading.Thread(target=self._monitor_and_scale, daemon=True)
        self._monitoring_thread.start()
        logger.info("Started horizontal scaling monitoring")
        
    def stop_monitoring(self) -> None:
        """Stop automatic scaling monitoring."""
        if self._monitoring_thread:
            self._stop_monitoring.set()
            self._monitoring_thread.join(timeout=10)
            logger.info("Stopped horizontal scaling monitoring")
            
    def scale_service(self, service_name: str, target_replicas: int) -> bool:
        """Scale a service to target number of replicas.
        
        Args:
            service_name: Name of the service to scale
            target_replicas: Target number of replicas
            
        Returns:
            True if scaling was successful
        """
        try:
            current_replicas = self.get_current_replicas(service_name)
            
            if current_replicas == target_replicas:
                logger.info(f"Service {service_name} already at target replicas: {target_replicas}")
                return True
                
            if self.orchestrator == 'docker-compose':
                return self._scale_docker_compose(service_name, target_replicas)
            elif self.orchestrator == 'kubernetes':
                return self._scale_kubernetes(service_name, target_replicas)
            elif self.orchestrator == 'docker-swarm':
                return self._scale_docker_swarm(service_name, target_replicas)
            else:
                logger.error(f"Unsupported orchestrator: {self.orchestrator}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to scale service {service_name}: {e}")
            return False
            
    def get_current_replicas(self, service_name: str) -> int:
        """Get current number of replicas for a service.
        
        Args:
            service_name: Name of the service
            
        Returns:
            Current number of replicas
        """
        try:
            if self.orchestrator == 'docker-compose':
                return self._get_docker_compose_replicas(service_name)
            elif self.orchestrator == 'kubernetes':
                return self._get_kubernetes_replicas(service_name)
            elif self.orchestrator == 'docker-swarm':
                return self._get_docker_swarm_replicas(service_name)
            else:
                return 1  # Default fallback
                
        except Exception as e:
            logger.error(f"Failed to get replicas for {service_name}: {e}")
            return 1
            
    def get_service_metrics(self, service_name: str) -> Dict[str, float]:
        """Get metrics for a service.
        
        Args:
            service_name: Name of the service
            
        Returns:
            Dictionary with service metrics
        """
        metrics = {
            'cpu_usage': 0.0,
            'memory_usage': 0.0,
            'request_rate': 0.0,
            'response_time': 0.0,
            'error_rate': 0.0
        }
        
        try:
            if self.orchestrator == 'docker-compose':
                metrics.update(self._get_docker_compose_metrics(service_name))
            elif self.orchestrator == 'kubernetes':
                metrics.update(self._get_kubernetes_metrics(service_name))
            elif self.orchestrator == 'docker-swarm':
                metrics.update(self._get_docker_swarm_metrics(service_name))
                
        except Exception as e:
            logger.error(f"Failed to get metrics for {service_name}: {e}")
            
        return metrics
        
    def calculate_target_replicas(self, service_name: str, 
                                metrics: Dict[str, float]) -> int:
        """Calculate target number of replicas based on metrics.
        
        Args:
            service_name: Name of the service
            metrics: Current service metrics
            
        Returns:
            Target number of replicas
        """
        policy = self.scaling_policies.get(service_name, {})
        
        min_replicas = policy.get('min_replicas', 1)
        max_replicas = policy.get('max_replicas', 10)
        target_cpu = policy.get('target_cpu', 70.0)
        target_memory = policy.get('target_memory', 80.0)
        target_request_rate = policy.get('target_request_rate', 100.0)
        
        current_replicas = self.get_current_replicas(service_name)
        
        # Calculate scaling factors based on different metrics
        scaling_factors = []
        
        # CPU-based scaling
        if metrics['cpu_usage'] > 0:
            cpu_factor = metrics['cpu_usage'] / target_cpu
            scaling_factors.append(cpu_factor)
            
        # Memory-based scaling
        if metrics['memory_usage'] > 0:
            memory_factor = metrics['memory_usage'] / target_memory
            scaling_factors.append(memory_factor)
            
        # Request rate-based scaling
        if metrics['request_rate'] > 0:
            request_factor = metrics['request_rate'] / target_request_rate
            scaling_factors.append(request_factor)
            
        # Use the maximum scaling factor (most constrained resource)
        if scaling_factors:
            max_factor = max(scaling_factors)
            target_replicas = int(current_replicas * max_factor)
        else:
            target_replicas = current_replicas
            
        # Apply bounds
        target_replicas = max(min_replicas, min(max_replicas, target_replicas))
        
        return target_replicas
        
    def should_scale(self, service_name: str, target_replicas: int) -> bool:
        """Determine if scaling should be performed.
        
        Args:
            service_name: Name of the service
            target_replicas: Target number of replicas
            
        Returns:
            True if scaling should be performed
        """
        current_replicas = self.get_current_replicas(service_name)
        
        # Don't scale if already at target
        if current_replicas == target_replicas:
            return False
            
        # Check cooldown period
        last_action = self.last_scaling_action.get(service_name, 0)
        if time.time() - last_action < self.cooldown_period:
            logger.debug(f"Scaling cooldown active for {service_name}")
            return False
            
        # Check if change is significant enough
        change_threshold = 0.2  # 20% change threshold
        if abs(target_replicas - current_replicas) / current_replicas < change_threshold:
            return False
            
        return True
        
    def get_scaling_history(self, service_name: str) -> List[Dict[str, Any]]:
        """Get scaling history for a service.
        
        Args:
            service_name: Name of the service
            
        Returns:
            List of scaling events
        """
        return self.metrics_history.get(service_name, [])
        
    def _monitor_and_scale(self) -> None:
        """Main monitoring and scaling loop."""
        while not self._stop_monitoring.wait(self.monitoring_interval):
            try:
                for service_name in self.scaling_policies.keys():
                    # Get current metrics
                    metrics = self.get_service_metrics(service_name)
                    
                    # Store metrics history
                    if service_name not in self.metrics_history:
                        self.metrics_history[service_name] = []
                        
                    self.metrics_history[service_name].append({
                        'timestamp': time.time(),
                        'metrics': metrics,
                        'replicas': self.get_current_replicas(service_name)
                    })
                    
                    # Keep only recent history (last 24 hours)
                    cutoff_time = time.time() - 86400
                    self.metrics_history[service_name] = [
                        entry for entry in self.metrics_history[service_name]
                        if entry['timestamp'] > cutoff_time
                    ]
                    
                    # Calculate target replicas
                    target_replicas = self.calculate_target_replicas(service_name, metrics)
                    
                    # Scale if needed
                    if self.should_scale(service_name, target_replicas):
                        logger.info(f"Scaling {service_name} to {target_replicas} replicas")
                        
                        if self.scale_service(service_name, target_replicas):
                            self.last_scaling_action[service_name] = time.time()
                            logger.info(f"Successfully scaled {service_name} to {target_replicas}")
                        else:
                            logger.error(f"Failed to scale {service_name}")
                            
            except Exception as e:
                logger.error(f"Error in scaling monitor: {e}")
                
    def _scale_docker_compose(self, service_name: str, target_replicas: int) -> bool:
        """Scale service using Docker Compose."""
        try:
            result = subprocess.run([
                'docker-compose', 'up', '-d', '--scale', 
                f'{service_name}={target_replicas}'
            ], capture_output=True, text=True, check=True)
            
            self.current_replicas[service_name] = target_replicas
            return True
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Docker Compose scaling failed: {e}")
            return False
            
    def _scale_kubernetes(self, service_name: str, target_replicas: int) -> bool:
        """Scale service using Kubernetes."""
        try:
            result = subprocess.run([
                'kubectl', 'scale', 'deployment', service_name,
                f'--replicas={target_replicas}'
            ], capture_output=True, text=True, check=True)
            
            self.current_replicas[service_name] = target_replicas
            return True
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Kubernetes scaling failed: {e}")
            return False
            
    def _scale_docker_swarm(self, service_name: str, target_replicas: int) -> bool:
        """Scale service using Docker Swarm."""
        try:
            result = subprocess.run([
                'docker', 'service', 'scale', 
                f'{service_name}={target_replicas}'
            ], capture_output=True, text=True, check=True)
            
            self.current_replicas[service_name] = target_replicas
            return True
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Docker Swarm scaling failed: {e}")
            return False
            
    def _get_docker_compose_replicas(self, service_name: str) -> int:
        """Get current replicas for Docker Compose service."""
        try:
            result = subprocess.run([
                'docker-compose', 'ps', '-q', service_name
            ], capture_output=True, text=True, check=True)
            
            # Count running containers
            containers = [line.strip() for line in result.stdout.split('\n') if line.strip()]
            return len(containers)
            
        except subprocess.CalledProcessError:
            return 1
            
    def _get_kubernetes_replicas(self, service_name: str) -> int:
        """Get current replicas for Kubernetes deployment."""
        try:
            result = subprocess.run([
                'kubectl', 'get', 'deployment', service_name, 
                '-o', 'jsonpath={.status.replicas}'
            ], capture_output=True, text=True, check=True)
            
            return int(result.stdout.strip() or '1')
            
        except (subprocess.CalledProcessError, ValueError):
            return 1
            
    def _get_docker_swarm_replicas(self, service_name: str) -> int:
        """Get current replicas for Docker Swarm service."""
        try:
            result = subprocess.run([
                'docker', 'service', 'ls', '--filter', f'name={service_name}',
                '--format', '{{.Replicas}}'
            ], capture_output=True, text=True, check=True)
            
            replicas_str = result.stdout.strip()
            if '/' in replicas_str:
                return int(replicas_str.split('/')[0])
            return 1
            
        except (subprocess.CalledProcessError, ValueError):
            return 1
            
    def _get_docker_compose_metrics(self, service_name: str) -> Dict[str, float]:
        """Get metrics for Docker Compose service."""
        metrics = {}
        
        try:
            # Get container stats
            result = subprocess.run([
                'docker', 'stats', '--no-stream', '--format',
                'table {{.Container}}\t{{.CPUPerc}}\t{{.MemPerc}}'
            ], capture_output=True, text=True, check=True)
            
            for line in result.stdout.split('\n')[1:]:  # Skip header
                if line.strip() and service_name in line:
                    parts = line.split('\t')
                    if len(parts) >= 3:
                        cpu_str = parts[1].replace('%', '')
                        mem_str = parts[2].replace('%', '')
                        
                        try:
                            metrics['cpu_usage'] = float(cpu_str)
                            metrics['memory_usage'] = float(mem_str)
                        except ValueError:
                            pass
                            
        except subprocess.CalledProcessError:
            pass
            
        return metrics
        
    def _get_kubernetes_metrics(self, service_name: str) -> Dict[str, float]:
        """Get metrics for Kubernetes deployment."""
        metrics = {}
        
        try:
            # Get CPU and memory usage from metrics server
            result = subprocess.run([
                'kubectl', 'top', 'pod', '-l', f'app={service_name}',
                '--no-headers'
            ], capture_output=True, text=True, check=True)
            
            total_cpu = 0
            total_memory = 0
            pod_count = 0
            
            for line in result.stdout.split('\n'):
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 3:
                        cpu_str = parts[1].replace('m', '')  # Remove millicores suffix
                        mem_str = parts[2].replace('Mi', '')  # Remove MiB suffix
                        
                        try:
                            total_cpu += int(cpu_str)
                            total_memory += int(mem_str)
                            pod_count += 1
                        except ValueError:
                            pass
                            
            if pod_count > 0:
                metrics['cpu_usage'] = total_cpu / pod_count / 10  # Convert to percentage
                metrics['memory_usage'] = total_memory / pod_count / 10  # Rough percentage
                
        except subprocess.CalledProcessError:
            pass
            
        return metrics
        
    def _get_docker_swarm_metrics(self, service_name: str) -> Dict[str, float]:
        """Get metrics for Docker Swarm service."""
        # Docker Swarm doesn't have built-in metrics, would need external monitoring
        return {}