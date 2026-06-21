"""
Logging configuration for the AI-driven IoT IDS system.

This module provides centralized logging configuration with support
for structured JSON logging, multiple output formats, and
configurable log levels for different system components.
"""

import logging
import logging.config
import json
import sys
from datetime import datetime
from typing import Dict, Any, Optional
from pathlib import Path


class JSONFormatter(logging.Formatter):
    """Custom JSON formatter for structured logging."""
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON."""
        log_entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno
        }
        
        # Add exception information if present
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)
        
        # Add extra fields from record
        for key, value in record.__dict__.items():
            if key not in ['name', 'msg', 'args', 'levelname', 'levelno', 
                          'pathname', 'filename', 'module', 'lineno', 
                          'funcName', 'created', 'msecs', 'relativeCreated',
                          'thread', 'threadName', 'processName', 'process',
                          'getMessage', 'exc_info', 'exc_text', 'stack_info']:
                log_entry[key] = value
        
        return json.dumps(log_entry, default=str)


class ComponentFilter(logging.Filter):
    """Filter logs by component name for focused debugging."""
    
    def __init__(self, component_name: str):
        super().__init__()
        self.component_name = component_name
    
    def filter(self, record: logging.LogRecord) -> bool:
        """Filter records based on component name."""
        return self.component_name in record.name


def setup_logging(config: Optional[Dict[str, Any]] = None, 
                 log_level: str = "INFO",
                 log_format: str = "json",
                 log_file: Optional[str] = None,
                 component_filter: Optional[str] = None) -> None:
    """
    Set up logging configuration for the IDS system.
    
    Args:
        config: Optional logging configuration dictionary
        log_level: Default log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_format: Log format ("json" or "text")
        log_file: Optional file path for log output
        component_filter: Optional component name filter
    """
    
    if config:
        logging.config.dictConfig(config)
        return
    
    # Default configuration
    log_config = {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "json": {
                "()": JSONFormatter
            },
            "text": {
                "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
                "datefmt": "%Y-%m-%d %H:%M:%S"
            }
        },
        "handlers": {
            "console": {
                "class": "logging.StreamHandler",
                "level": log_level,
                "formatter": log_format,
                "stream": sys.stdout
            }
        },
        "root": {
            "level": log_level,
            "handlers": ["console"]
        },
        "loggers": {
            "ai_iot_ids": {
                "level": log_level,
                "handlers": ["console"],
                "propagate": False
            }
        }
    }
    
    # Add file handler if log file is specified
    if log_file:
        log_file_path = Path(log_file)
        log_file_path.parent.mkdir(parents=True, exist_ok=True)
        
        log_config["handlers"]["file"] = {
            "class": "logging.handlers.RotatingFileHandler",
            "level": log_level,
            "formatter": log_format,
            "filename": str(log_file_path),
            "maxBytes": 10485760,  # 10MB
            "backupCount": 5
        }
        
        log_config["root"]["handlers"].append("file")
        log_config["loggers"]["ai_iot_ids"]["handlers"].append("file")
    
    # Add component filter if specified
    if component_filter:
        log_config["filters"] = {
            "component": {
                "()": ComponentFilter,
                "component_name": component_filter
            }
        }
        
        for handler in log_config["handlers"].values():
            handler["filters"] = ["component"]
    
    logging.config.dictConfig(log_config)


def get_logger(name: str, extra_fields: Optional[Dict[str, Any]] = None) -> logging.Logger:
    """
    Get a logger instance with optional extra fields.
    
    Args:
        name: Logger name (typically module name)
        extra_fields: Optional extra fields to include in all log messages
        
    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)
    
    if extra_fields:
        # Create adapter to add extra fields to all log messages
        logger = logging.LoggerAdapter(logger, extra_fields)
    
    return logger


def configure_component_logging(component_name: str, 
                              log_level: str = "INFO",
                              extra_fields: Optional[Dict[str, Any]] = None) -> logging.Logger:
    """
    Configure logging for a specific system component.
    
    Args:
        component_name: Name of the component
        log_level: Log level for this component
        extra_fields: Extra fields to include in component logs
        
    Returns:
        Configured logger for the component
    """
    logger_name = f"ai_iot_ids.{component_name}"
    logger = logging.getLogger(logger_name)
    logger.setLevel(getattr(logging, log_level.upper()))
    
    # Add component-specific extra fields
    component_extra = {"component": component_name}
    if extra_fields:
        component_extra.update(extra_fields)
    
    return logging.LoggerAdapter(logger, component_extra)


def log_performance_metrics(logger: logging.Logger, 
                          operation: str,
                          duration_ms: float,
                          **kwargs) -> None:
    """
    Log performance metrics in a structured format.
    
    Args:
        logger: Logger instance to use
        operation: Name of the operation being measured
        duration_ms: Duration in milliseconds
        **kwargs: Additional metrics to log
    """
    metrics = {
        "operation": operation,
        "duration_ms": duration_ms,
        "metric_type": "performance",
        **kwargs
    }
    
    logger.info("Performance metric recorded", extra=metrics)


def log_security_event(logger: logging.Logger,
                      event_type: str,
                      severity: str,
                      source_ip: str,
                      **kwargs) -> None:
    """
    Log security events in a structured format.
    
    Args:
        logger: Logger instance to use
        event_type: Type of security event
        severity: Event severity level
        source_ip: Source IP address
        **kwargs: Additional event details
    """
    security_event = {
        "event_type": event_type,
        "severity": severity,
        "source_ip": source_ip,
        "log_type": "security",
        **kwargs
    }
    
    logger.warning("Security event detected", extra=security_event)


def log_system_health(logger: logging.Logger,
                     component: str,
                     status: str,
                     metrics: Dict[str, Any]) -> None:
    """
    Log system health information in a structured format.
    
    Args:
        logger: Logger instance to use
        component: Component name
        status: Health status
        metrics: Health metrics dictionary
    """
    health_info = {
        "component": component,
        "status": status,
        "log_type": "health",
        **metrics
    }
    
    if status == "healthy":
        logger.info("Component health check passed", extra=health_info)
    else:
        logger.error("Component health check failed", extra=health_info)