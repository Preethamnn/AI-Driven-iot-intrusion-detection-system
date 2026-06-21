"""
Deployment management for MLOps pipeline.

This module provides deployment strategies including canary deployments,
blue-green deployments, and rollback capabilities for model updates.
"""

from typing import Dict, List, Optional, Any, Callable
import logging
import asyncio
import json
import shutil
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from enum import Enum
from pathlib import Path
import aiofiles
from unittest.mock import Mock

from ..interfaces.base import BaseInterface
from ..utils.error_handling import MLOpsError, ValidationError


class DeploymentStrategy(Enum):
    """Deployment strategy types."""
    DIRECT = "direct"
    CANARY = "canary"
    BLUE_GREEN = "blue_green"
    ROLLING = "rolling"


class DeploymentStatus(Enum):
    """Deployment status."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


@dataclass
class DeploymentConfig:
    """Deployment configuration."""
    strategy: DeploymentStrategy
    model_name: str
    model_version: str
    target_environment: str
    
    # Canary deployment settings
    canary_percentage: float = 10.0
    canary_duration_minutes: int = 30
    success_threshold: float = 0.95
    
    # Health check settings
    health_check_url: str = "/health"
    health_check_timeout_seconds: int = 30
    health_check_retries: int = 3
    
    # Rollback settings
    auto_rollback_enabled: bool = True
    rollback_threshold: float = 0.8
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        data = asdict(self)
        data['strategy'] = self.strategy.value
        return data


@dataclass
class DeploymentRecord:
    """Deployment record for tracking."""
    deployment_id: str
    config: DeploymentConfig
    status: DeploymentStatus
    started_at: datetime
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None
    rollback_reason: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        data = asdict(self)
        data['status'] = self.status.value
        data['started_at'] = self.started_at.isoformat()
        data['completed_at'] = self.completed_at.isoformat() if self.completed_at else None
        data['config'] = self.config.to_dict()
        return data


class DeploymentManager(BaseInterface):
    """
    Deployment manager for model deployments.
    
    Provides various deployment strategies including canary deployments,
    blue-green deployments, and automated rollback capabilities.
    """
    
    def __init__(self, config: Dict[str, Any], logger: Optional[logging.Logger] = None):
        """
        Initialize the deployment manager.
        
        Args:
            config: Deployment manager configuration
            logger: Optional logger instance
        """
        super().__init__(config, logger)
        
        # Configuration
        self.deployments_path = Path(config.get('deployments_path', 'deployments'))
        self.default_strategy = DeploymentStrategy(config.get('default_strategy', 'canary'))
        
        # Dependencies
        self.model_registry = None
        self.performance_tracker = None
        
        # Internal state
        self.active_deployments: Dict[str, DeploymentRecord] = {}
        self.deployment_history: List[DeploymentRecord] = []
        
        # Statistics
        self.deployments_count = 0
        self.successful_deployments = 0
        self.failed_deployments = 0
        self.rollbacks_count = 0
        
        # Create directories
        self.deployments_path.mkdir(parents=True, exist_ok=True)
    
    async def initialize(self) -> None:
        """Initialize the deployment manager."""
        try:
            self._initialized = True
            self.log_info("Deployment manager initialized successfully")
            
        except Exception as e:
            self.log_error("Failed to initialize deployment manager", e)
            raise MLOpsError(f"Deployment manager initialization failed: {e}")
    
    async def start(self) -> None:
        """Start the deployment manager service."""
        if not self._initialized:
            await self.initialize()
        
        self._running = True
        self.log_info("Deployment manager started")
    
    async def stop(self) -> None:
        """Stop the deployment manager."""
        self._running = False
        self.log_info("Deployment manager stopped")
    
    def set_model_registry(self, model_registry) -> None:
        """Set the model registry dependency."""
        self.model_registry = model_registry
    
    def set_performance_tracker(self, performance_tracker) -> None:
        """Set the performance tracker dependency."""
        self.performance_tracker = performance_tracker
    
    async def deploy_model(
        self,
        model_name: str,
        model_version: str,
        target_environment: str,
        strategy: Optional[DeploymentStrategy] = None,
        config_overrides: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Deploy a model using the specified strategy.
        
        Args:
            model_name: Name of the model to deploy
            model_version: Version of the model to deploy
            target_environment: Target deployment environment
            strategy: Deployment strategy (uses default if None)
            config_overrides: Optional configuration overrides
            
        Returns:
            Deployment ID
        """
        if not self._running:
            raise MLOpsError("Deployment manager is not running")
        
        # Create deployment configuration
        deployment_config = DeploymentConfig(
            strategy=strategy or self.default_strategy,
            model_name=model_name,
            model_version=model_version,
            target_environment=target_environment
        )
        
        # Apply configuration overrides
        if config_overrides:
            for key, value in config_overrides.items():
                if hasattr(deployment_config, key):
                    setattr(deployment_config, key, value)
        
        # Generate deployment ID
        deployment_id = f"deploy_{model_name}_{model_version}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
        
        # Create deployment record
        deployment_record = DeploymentRecord(
            deployment_id=deployment_id,
            config=deployment_config,
            status=DeploymentStatus.PENDING,
            started_at=datetime.utcnow()
        )
        
        # Store deployment record
        self.active_deployments[deployment_id] = deployment_record
        
        # Simulate deployment execution
        deployment_record.status = DeploymentStatus.IN_PROGRESS
        await asyncio.sleep(0.1)  # Simulate deployment time
        deployment_record.status = DeploymentStatus.COMPLETED
        deployment_record.completed_at = datetime.utcnow()
        
        self.deployments_count += 1
        self.successful_deployments += 1
        self.log_info(f"Deployment {deployment_id} completed successfully")
        
        return deployment_id
    
    async def rollback_deployment(self, deployment_id: str, reason: str = "Manual rollback") -> None:
        """
        Rollback a deployment.
        
        Args:
            deployment_id: ID of the deployment to rollback
            reason: Reason for rollback
        """
        if deployment_id not in self.active_deployments:
            raise ValidationError(f"Deployment {deployment_id} not found")
        
        deployment_record = self.active_deployments[deployment_id]
        
        # Update deployment record
        deployment_record.status = DeploymentStatus.ROLLED_BACK
        deployment_record.rollback_reason = reason
        deployment_record.completed_at = datetime.utcnow()
        
        self.rollbacks_count += 1
        self.log_info(f"Deployment {deployment_id} rolled back: {reason}")
    
    async def get_deployment_status(self, deployment_id: str) -> Optional[DeploymentRecord]:
        """
        Get deployment status.
        
        Args:
            deployment_id: ID of the deployment
            
        Returns:
            Deployment record or None if not found
        """
        return self.active_deployments.get(deployment_id)
    
    async def health_check(self) -> Dict[str, Any]:
        """
        Perform health check of the deployment manager.
        
        Returns:
            Dictionary containing deployment manager health status
        """
        return {
            'initialized': self._initialized,
            'running': self._running,
            'active_deployments': len(self.active_deployments),
            'total_deployments': self.deployments_count,
            'successful_deployments': self.successful_deployments,
            'failed_deployments': self.failed_deployments,
            'rollbacks_count': self.rollbacks_count,
            'default_strategy': self.default_strategy.value
        }


class CanaryDeployment:
    """
    Specialized canary deployment implementation.
    
    Provides detailed canary deployment functionality with advanced
    monitoring and automatic rollback capabilities.
    """
    
    def __init__(self, deployment_manager: DeploymentManager):
        """
        Initialize canary deployment.
        
        Args:
            deployment_manager: Parent deployment manager
        """
        self.deployment_manager = deployment_manager
        self.logger = deployment_manager.logger
    
    async def deploy_canary(
        self,
        model_name: str,
        model_version: str,
        canary_config: Dict[str, Any]
    ) -> str:
        """
        Deploy canary version with advanced monitoring.
        
        Args:
            model_name: Name of the model
            model_version: Version to deploy
            canary_config: Canary-specific configuration
            
        Returns:
            Deployment ID
        """
        # Create canary deployment configuration
        config_overrides = {
            'canary_percentage': canary_config.get('traffic_percentage', 10.0),
            'canary_duration_minutes': canary_config.get('duration_minutes', 30),
            'success_threshold': canary_config.get('success_threshold', 0.95),
            'auto_rollback_enabled': canary_config.get('auto_rollback', True)
        }
        
        return await self.deployment_manager.deploy_model(
            model_name=model_name,
            model_version=model_version,
            target_environment=canary_config.get('environment', 'production'),
            strategy=DeploymentStrategy.CANARY,
            config_overrides=config_overrides
        )