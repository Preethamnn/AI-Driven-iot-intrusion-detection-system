"""
FastAPI REST API for AI inference service.

This module provides REST endpoints for real-time threat detection,
model management, and health monitoring.
"""

from typing import Dict, List, Optional, Any, Union
import logging
import asyncio
from datetime import datetime
from contextlib import asynccontextmanager

try:
    from fastapi import FastAPI, HTTPException, Depends, status, BackgroundTasks
    from fastapi.responses import JSONResponse
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.middleware.gzip import GZipMiddleware
    from pydantic import BaseModel, Field, ValidationError
    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False
    FastAPI = None
    HTTPException = None
    BaseModel = None
    Field = None

from ...models.network_flow import NetworkFlow
from ...models.threat_detection import ThreatDetection
from ..hybrid_detection_engine import HybridDetectionEngine
from ..model_manager import ModelManager


# Request/Response Models
if FASTAPI_AVAILABLE:
    class InferenceRequest(BaseModel):
        """Request model for threat inference."""
        flows: List[NetworkFlow] = Field(description="List of network flows to analyze")
        model_names: Optional[List[str]] = Field(default=None, description="Specific models to use (optional)")
        include_explanations: bool = Field(default=True, description="Include feature importance explanations")
        
        class Config:
            schema_extra = {
                "example": {
                    "flows": [
                        {
                            "timestamp": "2024-01-15T10:30:00Z",
                            "source_ip": "192.168.1.100",
                            "destination_ip": "8.8.8.8",
                            "source_port": 45123,
                            "destination_port": 53,
                            "protocol": "UDP",
                            "bytes_sent": 64,
                            "bytes_received": 128,
                            "packets_sent": 1,
                            "packets_received": 1,
                            "duration_ms": 150,
                            "inter_arrival_mean_ms": 0.0,
                            "inter_arrival_std_ms": 0.0,
                            "jitter_ms": 0.0
                        }
                    ],
                    "model_names": ["isolation_forest", "xgboost"],
                    "include_explanations": True
                }
            }


    class InferenceResponse(BaseModel):
        """Response model for threat inference."""
        detections: List[ThreatDetection] = Field(description="List of threat detections")
        processing_time_ms: float = Field(description="Processing time in milliseconds")
        models_used: List[str] = Field(description="List of models that were used")
        status: str = Field(description="Processing status")
        
        class Config:
            schema_extra = {
                "example": {
                    "detections": [
                        {
                            "detection_id": "550e8400-e29b-41d4-a716-446655440001",
                            "timestamp": "2024-01-15T10:35:00Z",
                            "source_flow_id": "550e8400-e29b-41d4-a716-446655440000",
                            "device_id": "192.168.1.100",
                            "threat_score": 0.85,
                            "confidence": 0.92,
                            "severity": "high",
                            "attack_category": "reconnaissance"
                        }
                    ],
                    "processing_time_ms": 45.2,
                    "models_used": ["isolation_forest", "xgboost"],
                    "status": "success"
                }
            }


    class HealthResponse(BaseModel):
        """Response model for health check."""
        status: str = Field(description="Overall service status")
        timestamp: datetime = Field(description="Health check timestamp")
        version: str = Field(description="Service version")
        uptime_seconds: float = Field(description="Service uptime in seconds")
        detection_engine_health: Dict[str, Any] = Field(description="Detection engine health status")
        model_manager_health: Dict[str, Any] = Field(description="Model manager health status")


    class ModelInfo(BaseModel):
        """Model information response."""
        name: str = Field(description="Model name")
        version: str = Field(description="Model version")
        type: str = Field(description="Model type")
        loaded: bool = Field(description="Whether model is loaded")
        inference_count: int = Field(description="Number of inferences performed")
        last_inference_time: Optional[datetime] = Field(description="Last inference timestamp")
else:
    # Dummy classes when FastAPI is not available
    InferenceRequest = None
    InferenceResponse = None
    HealthResponse = None
    ModelInfo = None


class InferenceAPI:
    """
    FastAPI-based REST API for AI inference service.
    
    Provides endpoints for threat detection, model management,
    and service health monitoring.
    """
    
    def __init__(self, config: Dict[str, Any], logger: Optional[logging.Logger] = None):
        """
        Initialize the inference API.
        
        Args:
            config: API configuration
            logger: Optional logger instance
        """
        if not FASTAPI_AVAILABLE:
            raise ImportError("FastAPI is not installed. Install with: pip install fastapi uvicorn")
        
        self.config = config
        self.logger = logger or logging.getLogger(__name__)
        
        # Configuration
        self.host = config.get('host', '0.0.0.0')
        self.port = config.get('port', 8000)
        self.enable_cors = config.get('enable_cors', True)
        self.enable_gzip = config.get('enable_gzip', True)
        self.max_request_size = config.get('max_request_size', 10 * 1024 * 1024)  # 10MB
        self.request_timeout = config.get('request_timeout', 30)
        
        # Service components
        self.detection_engine: Optional[HybridDetectionEngine] = None
        self.model_manager: Optional[ModelManager] = None
        
        # Service state
        self.start_time = datetime.utcnow()
        self.version = config.get('version', '1.0.0')
        self.request_count = 0
        self.error_count = 0
    
    async def initialize(self) -> None:
        """Initialize the API service components."""
        try:
            # Initialize detection engine
            detection_config = self.config.get('detection_engine', {})
            self.detection_engine = HybridDetectionEngine(detection_config, self.logger)
            await self.detection_engine.initialize()
            await self.detection_engine.start()
            
            # Get model manager from detection engine
            self.model_manager = self.detection_engine.model_manager
            
            self.logger.info("Inference API initialized successfully")
            
        except Exception as e:
            self.logger.error("Failed to initialize inference API", exc_info=True)
            raise
    
    async def shutdown(self) -> None:
        """Shutdown the API service components."""
        try:
            if self.detection_engine:
                await self.detection_engine.stop()
            
            self.logger.info("Inference API shutdown completed")
            
        except Exception as e:
            self.logger.error("Error during API shutdown", exc_info=True)
    
    def get_uptime_seconds(self) -> float:
        """Get service uptime in seconds."""
        return (datetime.utcnow() - self.start_time).total_seconds()


# Global API instance
api_instance: Optional[InferenceAPI] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """FastAPI lifespan context manager."""
    global api_instance
    
    # Startup
    if api_instance:
        await api_instance.initialize()
    
    yield
    
    # Shutdown
    if api_instance:
        await api_instance.shutdown()


def create_app(config: Dict[str, Any]) -> FastAPI:
    """
    Create and configure FastAPI application.
    
    Args:
        config: Application configuration
        
    Returns:
        Configured FastAPI application
    """
    global api_instance
    
    # Create API instance
    api_instance = InferenceAPI(config)
    
    # Create FastAPI app
    app = FastAPI(
        title="AI-Driven IoT IDS Inference Service",
        description="REST API for real-time threat detection using hybrid ML and signature-based methods",
        version=api_instance.version,
        lifespan=lifespan
    )
    
    # Add middleware
    if api_instance.enable_cors:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )
    
    if api_instance.enable_gzip:
        app.add_middleware(GZipMiddleware, minimum_size=1000)
    
    # Dependency to get API instance
    def get_api() -> InferenceAPI:
        if api_instance is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Service not initialized"
            )
        return api_instance
    
    @app.post("/api/v1/detect", response_model=InferenceResponse)
    async def detect_threats(
        request: InferenceRequest,
        background_tasks: BackgroundTasks,
        api: InferenceAPI = Depends(get_api)
    ):
        """
        Detect threats in network flows.
        
        Analyzes network flows using hybrid detection engine combining
        signature-based rules and machine learning models.
        """
        start_time = datetime.utcnow()
        
        try:
            api.request_count += 1
            
            # Validate request
            if not request.flows:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="No flows provided for analysis"
                )
            
            if len(request.flows) > 1000:  # Reasonable limit
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Too many flows in single request (max 1000)"
                )
            
            # Perform threat detection
            detections = await api.detection_engine.detect_threats(request.flows)
            
            # Get models used (simplified)
            models_used = []
            if api.model_manager:
                models_used = api.model_manager.get_loaded_models()
            
            # Calculate processing time
            processing_time = (datetime.utcnow() - start_time).total_seconds() * 1000
            
            # Log detection summary in background
            background_tasks.add_task(
                log_detection_summary,
                len(request.flows),
                len(detections),
                processing_time,
                api.logger
            )
            
            return InferenceResponse(
                detections=detections,
                processing_time_ms=processing_time,
                models_used=models_used,
                status="success"
            )
            
        except ValidationError as e:
            api.error_count += 1
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Validation error: {str(e)}"
            )
        except Exception as e:
            api.error_count += 1
            api.logger.error(f"Threat detection failed: {str(e)}", exc_info=True)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Internal server error during threat detection"
            )
    
    @app.get("/api/v1/health", response_model=HealthResponse)
    async def health_check(api: InferenceAPI = Depends(get_api)):
        """
        Get service health status.
        
        Returns comprehensive health information including component status,
        performance metrics, and service availability.
        """
        try:
            # Get component health
            detection_engine_health = {}
            model_manager_health = {}
            
            if api.detection_engine:
                detection_engine_health = await api.detection_engine.health_check()
            
            if api.model_manager:
                model_manager_health = await api.model_manager.health_check()
            
            # Determine overall status
            overall_status = "healthy"
            if not detection_engine_health.get('running', False):
                overall_status = "degraded"
            
            return HealthResponse(
                status=overall_status,
                timestamp=datetime.utcnow(),
                version=api.version,
                uptime_seconds=api.get_uptime_seconds(),
                detection_engine_health=detection_engine_health,
                model_manager_health=model_manager_health
            )
            
        except Exception as e:
            api.logger.error(f"Health check failed: {str(e)}", exc_info=True)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Health check failed"
            )
    
    @app.get("/api/v1/models", response_model=List[ModelInfo])
    async def list_models(api: InferenceAPI = Depends(get_api)):
        """
        List available models.
        
        Returns information about all loaded models including
        their status, version, and performance metrics.
        """
        try:
            models = []
            
            if api.model_manager:
                for model_name in api.model_manager.get_loaded_models():
                    model_info = api.model_manager.get_model_info(model_name)
                    if model_info:
                        models.append(ModelInfo(
                            name=model_info.get('name', model_name),
                            version=model_info.get('version', '1.0.0'),
                            type=model_info.get('type', 'unknown'),
                            loaded=api.model_manager.is_model_loaded(model_name),
                            inference_count=model_info.get('inference_count', 0),
                            last_inference_time=None  # Would need to track this
                        ))
            
            return models
            
        except Exception as e:
            api.logger.error(f"Model listing failed: {str(e)}", exc_info=True)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to list models"
            )
    
    @app.get("/api/v1/models/{model_name}/info")
    async def get_model_info(model_name: str, api: InferenceAPI = Depends(get_api)):
        """
        Get detailed information about a specific model.
        
        Returns comprehensive model information including configuration,
        performance metrics, and health status.
        """
        try:
            if not api.model_manager or not api.model_manager.is_model_loaded(model_name):
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Model '{model_name}' not found or not loaded"
                )
            
            model_info = api.model_manager.get_model_info(model_name)
            return model_info
            
        except HTTPException:
            raise
        except Exception as e:
            api.logger.error(f"Model info retrieval failed: {str(e)}", exc_info=True)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to retrieve model information"
            )
    
    @app.get("/api/v1/stats")
    async def get_statistics(api: InferenceAPI = Depends(get_api)):
        """
        Get service statistics.
        
        Returns performance and usage statistics for the inference service.
        """
        try:
            stats = {
                'service': {
                    'uptime_seconds': api.get_uptime_seconds(),
                    'request_count': api.request_count,
                    'error_count': api.error_count,
                    'error_rate': api.error_count / max(1, api.request_count)
                }
            }
            
            # Add detection engine stats
            if api.detection_engine:
                detection_stats = api.detection_engine.get_detection_statistics()
                stats['detection_engine'] = detection_stats
            
            return stats
            
        except Exception as e:
            api.logger.error(f"Statistics retrieval failed: {str(e)}", exc_info=True)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to retrieve statistics"
            )
    
    @app.get("/")
    async def root():
        """Root endpoint with service information."""
        return {
            "service": "AI-Driven IoT IDS Inference Service",
            "version": api_instance.version if api_instance else "unknown",
            "status": "running",
            "docs": "/docs",
            "health": "/api/v1/health"
        }
    
    return app


async def log_detection_summary(flow_count: int, detection_count: int, 
                              processing_time: float, logger: logging.Logger):
    """Log detection summary in background."""
    logger.info(
        f"Detection completed: {flow_count} flows analyzed, "
        f"{detection_count} threats detected, "
        f"{processing_time:.2f}ms processing time"
    )