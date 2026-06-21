"""
Base interface definitions for the AI-driven IoT IDS system.

This module provides the foundational abstract base class that all
system interfaces inherit from, ensuring consistent error handling
and lifecycle management.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, Optional
import logging


class BaseInterface(ABC):
    """
    Abstract base class for all system interfaces.
    
    Provides common functionality for configuration management,
    logging, and lifecycle operations that all components need.
    """
    
    def __init__(self, config: Dict[str, Any], logger: Optional[logging.Logger] = None):
        """
        Initialize the base interface.
        
        Args:
            config: Configuration dictionary for the component
            logger: Optional logger instance, creates default if not provided
        """
        self.config = config
        self.logger = logger or logging.getLogger(self.__class__.__name__)
        self._initialized = False
        self._running = False
    
    @abstractmethod
    async def initialize(self) -> None:
        """
        Initialize the component with its configuration.
        
        This method should be called before any other operations
        and should set up all necessary resources.
        """
        pass
    
    @abstractmethod
    async def start(self) -> None:
        """
        Start the component's main operations.
        
        This method should begin the component's primary functionality
        and should only be called after initialization.
        """
        pass
    
    @abstractmethod
    async def stop(self) -> None:
        """
        Stop the component's operations and clean up resources.
        
        This method should gracefully shut down the component
        and release any held resources.
        """
        pass
    
    @abstractmethod
    async def health_check(self) -> Dict[str, Any]:
        """
        Perform a health check of the component.
        
        Returns:
            Dictionary containing health status and metrics
        """
        pass
    
    def is_initialized(self) -> bool:
        """Check if the component has been initialized."""
        return self._initialized
    
    def is_running(self) -> bool:
        """Check if the component is currently running."""
        return self._running
    
    def get_config(self, key: str, default: Any = None) -> Any:
        """
        Get a configuration value by key.
        
        Args:
            key: Configuration key to retrieve
            default: Default value if key is not found
            
        Returns:
            Configuration value or default
        """
        return self.config.get(key, default)
    
    def update_config(self, new_config: Dict[str, Any]) -> None:
        """
        Update the component's configuration.
        
        Args:
            new_config: New configuration dictionary to merge
        """
        self.config.update(new_config)
        self.logger.info(f"Configuration updated for {self.__class__.__name__}")
    
    def log_error(self, message: str, exception: Optional[Exception] = None) -> None:
        """
        Log an error message with optional exception details.
        
        Args:
            message: Error message to log
            exception: Optional exception to include in log
        """
        if exception:
            self.logger.error(f"{message}: {str(exception)}", exc_info=True)
        else:
            self.logger.error(message)
    
    def log_info(self, message: str) -> None:
        """
        Log an informational message.
        
        Args:
            message: Information message to log
        """
        self.logger.info(message)
    
    def log_warning(self, message: str) -> None:
        """
        Log a warning message.
        
        Args:
            message: Warning message to log
        """
        self.logger.warning(message)