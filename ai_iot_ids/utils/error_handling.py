"""
Error handling framework for the AI-driven IoT IDS system.

This module defines custom exception classes and error handling
utilities for consistent error management across all system
components.
"""

import traceback
from typing import Dict, Any, Optional, List
from datetime import datetime
from enum import Enum


class ErrorSeverity(str, Enum):
    """Enumeration of error severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ErrorCategory(str, Enum):
    """Enumeration of error categories."""
    CONFIGURATION = "configuration"
    NETWORK = "network"
    AUTHENTICATION = "authentication"
    MODEL = "model"
    DATA = "data"
    SYSTEM = "system"
    SECURITY = "security"


class IDSError(Exception):
    """
    Base exception class for all IDS-specific errors.
    
    Provides structured error information including severity,
    category, context, and remediation suggestions.
    """
    
    def __init__(self, 
                 message: str,
                 severity: ErrorSeverity = ErrorSeverity.MEDIUM,
                 category: ErrorCategory = ErrorCategory.SYSTEM,
                 component: Optional[str] = None,
                 context: Optional[Dict[str, Any]] = None,
                 remediation: Optional[str] = None,
                 cause: Optional[Exception] = None):
        """
        Initialize IDS error with structured information.
        
        Args:
            message: Human-readable error message
            severity: Error severity level
            category: Error category for classification
            component: Component where error occurred
            context: Additional context information
            remediation: Suggested remediation steps
            cause: Underlying exception that caused this error
        """
        super().__init__(message)
        self.message = message
        self.severity = severity
        self.category = category
        self.component = component
        self.context = context or {}
        self.remediation = remediation
        self.cause = cause
        self.timestamp = datetime.utcnow()
        self.error_id = self._generate_error_id()
    
    def _generate_error_id(self) -> str:
        """Generate unique error identifier."""
        import hashlib
        error_data = f"{self.timestamp.isoformat()}{self.component}{self.message}"
        return hashlib.md5(error_data.encode()).hexdigest()[:8]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert error to dictionary for logging and serialization."""
        return {
            "error_id": self.error_id,
            "timestamp": self.timestamp.isoformat(),
            "message": self.message,
            "severity": self.severity.value,
            "category": self.category.value,
            "component": self.component,
            "context": self.context,
            "remediation": self.remediation,
            "cause": str(self.cause) if self.cause else None,
            "traceback": traceback.format_exc() if self.cause else None
        }
    
    def is_critical(self) -> bool:
        """Check if error is critical severity."""
        return self.severity == ErrorSeverity.CRITICAL
    
    def is_recoverable(self) -> bool:
        """Check if error is potentially recoverable."""
        return self.severity in [ErrorSeverity.LOW, ErrorSeverity.MEDIUM]


class ConfigurationError(IDSError):
    """Error related to system configuration issues."""
    
    def __init__(self, message: str, config_key: Optional[str] = None, 
                 config_value: Optional[Any] = None, **kwargs):
        ctx = kwargs.pop('context', {})
        ctx.update({"config_key": config_key, "config_value": config_value})
        super().__init__(
            message=message,
            category=ErrorCategory.CONFIGURATION,
            context=ctx,
            **kwargs
        )
        self.config_key = config_key
        self.config_value = config_value


class NetworkError(IDSError):
    """Error related to network operations and connectivity."""
    
    def __init__(self, message: str, endpoint: Optional[str] = None,
                 status_code: Optional[int] = None, **kwargs):
        super().__init__(
            message=message,
            category=ErrorCategory.NETWORK,
            context={"endpoint": endpoint, "status_code": status_code},
            **kwargs
        )
        self.endpoint = endpoint
        self.status_code = status_code


class AuthenticationError(IDSError):
    """Error related to authentication and authorization."""
    
    def __init__(self, message: str, user: Optional[str] = None,
                 resource: Optional[str] = None, **kwargs):
        super().__init__(
            message=message,
            category=ErrorCategory.AUTHENTICATION,
            severity=ErrorSeverity.HIGH,
            context={"user": user, "resource": resource},
            **kwargs
        )
        self.user = user
        self.resource = resource


class ModelError(IDSError):
    """Error related to ML model operations."""
    
    def __init__(self, message: str, model_name: Optional[str] = None,
                 model_version: Optional[str] = None, **kwargs):
        super().__init__(
            message=message,
            category=ErrorCategory.MODEL,
            context={"model_name": model_name, "model_version": model_version},
            **kwargs
        )
        self.model_name = model_name
        self.model_version = model_version


class DataError(IDSError):
    """Error related to data processing and validation."""
    
    def __init__(self, message: str, data_type: Optional[str] = None,
                 validation_errors: Optional[List[str]] = None, **kwargs):
        super().__init__(
            message=message,
            category=ErrorCategory.DATA,
            context={"data_type": data_type, "validation_errors": validation_errors},
            **kwargs
        )
        self.data_type = data_type
        self.validation_errors = validation_errors or []


class SecurityError(IDSError):
    """Error related to security violations and threats."""
    
    def __init__(self, message: str, threat_type: Optional[str] = None,
                 source_ip: Optional[str] = None, **kwargs):
        super().__init__(
            message=message,
            category=ErrorCategory.SECURITY,
            severity=ErrorSeverity.HIGH,
            context={"threat_type": threat_type, "source_ip": source_ip},
            **kwargs
        )
        self.threat_type = threat_type
        self.source_ip = source_ip


class MLOpsError(IDSError):
    """Error related to MLOps operations and model lifecycle management."""
    
    def __init__(self, message: str, operation: Optional[str] = None,
                 model_name: Optional[str] = None, **kwargs):
        super().__init__(
            message=message,
            category=ErrorCategory.MODEL,
            context={"operation": operation, "model_name": model_name},
            **kwargs
        )
        self.operation = operation
        self.model_name = model_name


class ValidationError(IDSError):
    """Error related to data validation and input validation."""
    
    def __init__(self, message: str, field: Optional[str] = None,
                 value: Optional[Any] = None, **kwargs):
        super().__init__(
            message=message,
            category=ErrorCategory.DATA,
            severity=ErrorSeverity.MEDIUM,
            context={"field": field, "value": value},
            **kwargs
        )
        self.field = field
        self.value = value


class ErrorHandler:
    """Centralized error handling and reporting."""
    
    def __init__(self, logger=None):
        """Initialize error handler with optional logger."""
        self.logger = logger
        self.error_counts = {}
        self.recent_errors = []
        self.max_recent_errors = 100
    
    def handle_error(self, error: IDSError, 
                    suppress_logging: bool = False) -> None:
        """
        Handle an IDS error with logging and tracking.
        
        Args:
            error: IDS error to handle
            suppress_logging: Whether to suppress logging output
        """
        # Track error statistics
        error_key = f"{error.category.value}:{error.component}"
        self.error_counts[error_key] = self.error_counts.get(error_key, 0) + 1
        
        # Add to recent errors list
        self.recent_errors.append(error)
        if len(self.recent_errors) > self.max_recent_errors:
            self.recent_errors.pop(0)
        
        # Log error if logger is available and not suppressed
        if self.logger and not suppress_logging:
            log_level = self._get_log_level(error.severity)
            self.logger.log(log_level, f"IDS Error: {error.message}", 
                          extra=error.to_dict())
    
    def _get_log_level(self, severity: ErrorSeverity) -> int:
        """Map error severity to logging level."""
        import logging
        mapping = {
            ErrorSeverity.LOW: logging.INFO,
            ErrorSeverity.MEDIUM: logging.WARNING,
            ErrorSeverity.HIGH: logging.ERROR,
            ErrorSeverity.CRITICAL: logging.CRITICAL
        }
        return mapping.get(severity, logging.ERROR)
    
    def get_error_statistics(self) -> Dict[str, Any]:
        """Get error statistics and metrics."""
        total_errors = sum(self.error_counts.values())
        critical_errors = len([e for e in self.recent_errors 
                             if e.severity == ErrorSeverity.CRITICAL])
        
        return {
            "total_errors": total_errors,
            "critical_errors": critical_errors,
            "error_counts_by_component": self.error_counts,
            "recent_error_count": len(self.recent_errors),
            "most_common_errors": self._get_most_common_errors()
        }
    
    def _get_most_common_errors(self, limit: int = 5) -> List[Dict[str, Any]]:
        """Get most common error types."""
        sorted_errors = sorted(self.error_counts.items(), 
                             key=lambda x: x[1], reverse=True)
        return [{"error_type": error_type, "count": count} 
                for error_type, count in sorted_errors[:limit]]
    
    def clear_error_history(self) -> None:
        """Clear error tracking history."""
        self.error_counts.clear()
        self.recent_errors.clear()


def handle_exceptions(error_handler: Optional[ErrorHandler] = None):
    """
    Decorator for automatic exception handling and conversion to IDS errors.
    
    Args:
        error_handler: Optional error handler instance
    """
    def decorator(func):
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except IDSError:
                # Re-raise IDS errors as-is
                raise
            except Exception as e:
                # Convert generic exceptions to IDS errors
                ids_error = IDSError(
                    message=f"Unexpected error in {func.__name__}: {str(e)}",
                    severity=ErrorSeverity.HIGH,
                    component=func.__module__,
                    cause=e
                )
                
                if error_handler:
                    error_handler.handle_error(ids_error)
                
                raise ids_error
        return wrapper
    return decorator


def create_error_context(component: str, operation: str, 
                        **kwargs) -> Dict[str, Any]:
    """
    Create standardized error context dictionary.
    
    Args:
        component: Component name where error occurred
        operation: Operation being performed when error occurred
        **kwargs: Additional context information
        
    Returns:
        Standardized error context dictionary
    """
    context = {
        "component": component,
        "operation": operation,
        "timestamp": datetime.utcnow().isoformat(),
        **kwargs
    }
    return context