"""
Configuration parsing utilities for the AI-driven IoT IDS system.

This module provides YAML configuration parsing with validation,
hot-reloading support, and round-trip consistency for system
configuration management.
"""

import yaml
from typing import Dict, Any, Optional, Type, TypeVar
from pathlib import Path
from abc import ABC, abstractmethod
import json
from datetime import datetime
from enum import Enum

from ..models.system_configuration import SystemConfiguration
from .error_handling import ConfigurationError, ErrorSeverity

T = TypeVar('T')


# Custom YAML representer for Enum types
def enum_representer(dumper, data):
    """Represent Enum values as their string value in YAML."""
    return dumper.represent_str(data.value)


# Register the representer for all Enum types with both SafeDumper and Dumper
yaml.add_multi_representer(Enum, enum_representer, Dumper=yaml.SafeDumper)
yaml.add_multi_representer(Enum, enum_representer, Dumper=yaml.Dumper)


class ConfigParser(ABC):
    """Abstract base class for configuration parsers."""
    
    @abstractmethod
    def parse(self, content: str, model_class: Type[T]) -> T:
        """Parse configuration content into model instance."""
        pass
    
    @abstractmethod
    def serialize(self, config_object: T) -> str:
        """Serialize configuration object back to string format."""
        pass
    
    @abstractmethod
    def validate_syntax(self, content: str) -> bool:
        """Validate configuration syntax without parsing."""
        pass


class YAMLConfigParser(ConfigParser):
    """
    YAML configuration parser with validation and round-trip support.
    
    Provides parsing of YAML configuration files into Pydantic models
    with comprehensive error handling and validation.
    """
    
    def __init__(self, preserve_order: bool = True):
        """
        Initialize YAML parser.
        
        Args:
            preserve_order: Whether to preserve key order in YAML output
        """
        self.preserve_order = preserve_order
        if preserve_order:
            # Use ordered dict loader to preserve key order
            self.yaml_loader = yaml.SafeLoader
            self.yaml_dumper = yaml.SafeDumper
        else:
            self.yaml_loader = yaml.SafeLoader
            self.yaml_dumper = yaml.SafeDumper
    
    def parse(self, content: str, model_class: Type[T]) -> T:
        """
        Parse YAML content into Pydantic model instance.
        
        Args:
            content: YAML content string
            model_class: Pydantic model class to parse into
            
        Returns:
            Parsed model instance
            
        Raises:
            ConfigurationError: If parsing or validation fails
        """
        try:
            # Parse YAML content
            yaml_data = yaml.load(content, Loader=self.yaml_loader)
            
            if yaml_data is None:
                raise ConfigurationError(
                    "Configuration file is empty or contains only comments",
                    severity=ErrorSeverity.HIGH
                )
            
            # Validate and create model instance
            config_instance = model_class(**yaml_data)
            return config_instance
            
        except yaml.YAMLError as e:
            raise ConfigurationError(
                f"YAML syntax error: {str(e)}",
                severity=ErrorSeverity.HIGH,
                remediation="Check YAML syntax and indentation"
            )
        except TypeError as e:
            raise ConfigurationError(
                f"Configuration structure error: {str(e)}",
                severity=ErrorSeverity.HIGH,
                remediation="Check configuration keys and structure against schema"
            )
        except ValueError as e:
            raise ConfigurationError(
                f"Configuration validation error: {str(e)}",
                severity=ErrorSeverity.HIGH,
                remediation="Check configuration values against allowed ranges"
            )
    
    def serialize(self, config_object: T) -> str:
        """
        Serialize configuration object back to YAML string.
        
        Args:
            config_object: Configuration object to serialize
            
        Returns:
            YAML string representation
        """
        try:
            # Convert Pydantic model to dictionary
            if hasattr(config_object, 'model_dump'):
                config_dict = config_object.model_dump()
            elif hasattr(config_object, 'dict'):
                config_dict = config_object.dict()
            else:
                config_dict = dict(config_object)
            
            # Serialize to YAML with proper formatting
            yaml_content = yaml.dump(
                config_dict,
                Dumper=self.yaml_dumper,
                default_flow_style=False,
                indent=2,
                width=80,
                sort_keys=not self.preserve_order
            )
            
            return yaml_content
            
        except Exception as e:
            raise ConfigurationError(
                f"Failed to serialize configuration: {str(e)}",
                severity=ErrorSeverity.MEDIUM
            )
    
    def validate_syntax(self, content: str) -> bool:
        """
        Validate YAML syntax without full parsing.
        
        Args:
            content: YAML content to validate
            
        Returns:
            True if syntax is valid, False otherwise
        """
        try:
            yaml.load(content, Loader=self.yaml_loader)
            return True
        except yaml.YAMLError:
            return False
    
    def parse_file(self, file_path: Path, model_class: Type[T]) -> T:
        """
        Parse YAML configuration file.
        
        Args:
            file_path: Path to YAML configuration file
            model_class: Pydantic model class to parse into
            
        Returns:
            Parsed configuration instance
            
        Raises:
            ConfigurationError: If file cannot be read or parsed
        """
        try:
            if not file_path.exists():
                raise ConfigurationError(
                    f"Configuration file not found: {file_path}",
                    severity=ErrorSeverity.CRITICAL,
                    remediation="Create configuration file or check file path"
                )
            
            content = file_path.read_text(encoding='utf-8')
            return self.parse(content, model_class)
            
        except IOError as e:
            raise ConfigurationError(
                f"Failed to read configuration file {file_path}: {str(e)}",
                severity=ErrorSeverity.HIGH,
                remediation="Check file permissions and disk space"
            )
    
    def write_file(self, config_object: T, file_path: Path) -> None:
        """
        Write configuration object to YAML file.
        
        Args:
            config_object: Configuration object to write
            file_path: Path where to write the configuration
            
        Raises:
            ConfigurationError: If file cannot be written
        """
        try:
            # Ensure parent directory exists
            file_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Serialize and write configuration
            yaml_content = self.serialize(config_object)
            file_path.write_text(yaml_content, encoding='utf-8')
            
        except IOError as e:
            raise ConfigurationError(
                f"Failed to write configuration file {file_path}: {str(e)}",
                severity=ErrorSeverity.HIGH,
                remediation="Check file permissions and disk space"
            )


class ConfigurationManager:
    """
    Configuration manager with hot-reloading and validation support.
    
    Manages system configuration with file watching, validation,
    and atomic updates for operational flexibility.
    """
    
    def __init__(self, parser: ConfigParser = None):
        """
        Initialize configuration manager.
        
        Args:
            parser: Configuration parser to use (defaults to YAML parser)
        """
        self.parser = parser or YAMLConfigParser()
        self.current_config: Optional[SystemConfiguration] = None
        self.config_file_path: Optional[Path] = None
        self.last_modified: Optional[datetime] = None
        self.validation_errors: List[str] = []
    
    def load_configuration(self, file_path: Path) -> SystemConfiguration:
        """
        Load configuration from file.
        
        Args:
            file_path: Path to configuration file
            
        Returns:
            Loaded configuration instance
        """
        self.config_file_path = file_path
        self.current_config = self.parser.parse_file(file_path, SystemConfiguration)
        self.last_modified = datetime.fromtimestamp(file_path.stat().st_mtime)
        
        # Validate configuration
        self.validate_configuration(self.current_config)
        
        return self.current_config
    
    def save_configuration(self, config: SystemConfiguration, 
                          file_path: Optional[Path] = None) -> None:
        """
        Save configuration to file.
        
        Args:
            config: Configuration to save
            file_path: Optional file path (uses current path if not provided)
        """
        target_path = file_path or self.config_file_path
        if not target_path:
            raise ConfigurationError(
                "No file path specified for saving configuration",
                severity=ErrorSeverity.HIGH
            )
        
        # Validate before saving
        self.validate_configuration(config)
        
        # Write to file
        self.parser.write_file(config, target_path)
        self.current_config = config
        self.last_modified = datetime.utcnow()
    
    def validate_configuration(self, config: SystemConfiguration) -> None:
        """
        Validate configuration object.
        
        Args:
            config: Configuration to validate
            
        Raises:
            ConfigurationError: If validation fails
        """
        self.validation_errors.clear()
        
        try:
            # Use built-in validation
            config.validate_configuration()
        except ValueError as e:
            self.validation_errors.append(str(e))
            raise ConfigurationError(
                f"Configuration validation failed: {str(e)}",
                severity=ErrorSeverity.HIGH,
                context={"validation_errors": self.validation_errors}
            )
    
    def check_for_updates(self) -> bool:
        """
        Check if configuration file has been modified.
        
        Returns:
            True if file has been modified since last load
        """
        if not self.config_file_path or not self.last_modified:
            return False
        
        try:
            current_mtime = datetime.fromtimestamp(
                self.config_file_path.stat().st_mtime
            )
            return current_mtime > self.last_modified
        except OSError:
            return False
    
    def reload_if_changed(self) -> bool:
        """
        Reload configuration if file has changed.
        
        Returns:
            True if configuration was reloaded, False otherwise
        """
        if self.check_for_updates():
            try:
                self.load_configuration(self.config_file_path)
                return True
            except ConfigurationError:
                # Log error but don't crash - keep current config
                return False
        return False
    
    def test_round_trip_consistency(self, config: SystemConfiguration) -> bool:
        """
        Test round-trip consistency: parse -> serialize -> parse.
        
        Args:
            config: Configuration to test
            
        Returns:
            True if round-trip produces equivalent configuration
        """
        try:
            # Serialize configuration
            serialized = self.parser.serialize(config)
            
            # Parse it back
            parsed_back = self.parser.parse(serialized, SystemConfiguration)
            
            # Compare original and round-trip result
            original_dict = config.model_dump() if hasattr(config, 'model_dump') else config.dict()
            parsed_dict = parsed_back.model_dump() if hasattr(parsed_back, 'model_dump') else parsed_back.dict()
            return original_dict == parsed_dict
            
        except Exception:
            return False
    
    def get_configuration_summary(self) -> Dict[str, Any]:
        """
        Get summary of current configuration.
        
        Returns:
            Dictionary with configuration summary
        """
        if not self.current_config:
            return {"status": "no_configuration_loaded"}
        
        return {
            "status": "loaded",
            "file_path": str(self.config_file_path) if self.config_file_path else None,
            "last_modified": self.last_modified.isoformat() if self.last_modified else None,
            "enabled_models": self.current_config.get_enabled_models(),
            "total_retention_days": self.current_config.get_total_retention_days(),
            "high_performance_mode": self.current_config.is_high_performance_mode(),
            "validation_errors": self.validation_errors
        }