"""
Integration module for AI-driven IoT IDS system.

This module provides system orchestration and component wiring
for end-to-end data flow validation and system integration.
"""

from .system_orchestrator import SystemOrchestrator, ProcessingMetrics
from .component_factory import ComponentFactory
from .data_flow_validator import DataFlowValidator, ValidationResult

__all__ = [
    'SystemOrchestrator', 
    'ProcessingMetrics',
    'ComponentFactory',
    'DataFlowValidator',
    'ValidationResult'
]