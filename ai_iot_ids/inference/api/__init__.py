"""
REST API components for the AI inference service.

This package provides FastAPI-based REST endpoints and gRPC services
for real-time threat detection and model management.
"""

from .rest_api import create_app, InferenceAPI
from .grpc_service import GRPCInferenceService

__all__ = [
    'create_app',
    'InferenceAPI',
    'GRPCInferenceService'
]