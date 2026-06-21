"""
gRPC service for high-performance AI inference.

This module provides gRPC endpoints for real-time threat detection
with lower latency and higher throughput than REST API.
"""

from typing import Dict, List, Optional, Any, AsyncIterator
import logging
import asyncio
from datetime import datetime
import json

try:
    import grpc
    from grpc import aio
    GRPC_AVAILABLE = True
except ImportError:
    GRPC_AVAILABLE = False
    grpc = None
    aio = None

from ...models.network_flow import NetworkFlow
from ...models.threat_detection import ThreatDetection
from ..hybrid_detection_engine import HybridDetectionEngine


# Protocol Buffer definitions (simplified - would normally be generated)
class InferenceRequest:
    """gRPC inference request message."""
    
    def __init__(self):
        self.flows = []
        self.model_names = []
        self.include_explanations = True


class InferenceResponse:
    """gRPC inference response message."""
    
    def __init__(self):
        self.detections = []
        self.processing_time_ms = 0.0
        self.models_used = []
        self.status = "success"


class HealthRequest:
    """gRPC health check request message."""
    
    def __init__(self):
        self.service = ""


class HealthResponse:
    """gRPC health check response message."""
    
    def __init__(self):
        self.status = "SERVING"
        self.timestamp = ""
        self.details = {}


class GRPCInferenceService:
    """
    gRPC service for AI inference.
    
    Provides high-performance gRPC endpoints for threat detection
    with support for streaming and batch processing.
    """
    
    def __init__(self, config: Dict[str, Any], logger: Optional[logging.Logger] = None):
        """
        Initialize the gRPC inference service.
        
        Args:
            config: Service configuration
            logger: Optional logger instance
        """
        if not GRPC_AVAILABLE:
            raise ImportError("gRPC is not installed. Install with: pip install grpcio grpcio-tools")
        
        self.config = config
        self.logger = logger or logging.getLogger(__name__)
        
        # Configuration
        self.host = config.get('host', '0.0.0.0')
        self.port = config.get('port', 50051)
        self.max_workers = config.get('max_workers', 10)
        self.max_message_length = config.get('max_message_length', 100 * 1024 * 1024)  # 100MB
        
        # Service components
        self.detection_engine: Optional[HybridDetectionEngine] = None
        self.server: Optional[aio.Server] = None
        
        # Service state
        self.start_time = datetime.utcnow()
        self.request_count = 0
        self.error_count = 0
    
    async def initialize(self) -> None:
        """Initialize the gRPC service components."""
        try:
            # Initialize detection engine
            detection_config = self.config.get('detection_engine', {})
            self.detection_engine = HybridDetectionEngine(detection_config, self.logger)
            await self.detection_engine.initialize()
            await self.detection_engine.start()
            
            self.logger.info("gRPC inference service initialized successfully")
            
        except Exception as e:
            self.logger.error("Failed to initialize gRPC inference service", exc_info=True)
            raise
    
    async def start_server(self) -> None:
        """Start the gRPC server."""
        try:
            # Create server
            self.server = aio.server(
                options=[
                    ('grpc.max_send_message_length', self.max_message_length),
                    ('grpc.max_receive_message_length', self.max_message_length),
                ]
            )
            
            # Add service to server (would normally use generated code)
            # inference_pb2_grpc.add_InferenceServiceServicer_to_server(self, self.server)
            
            # Add insecure port
            listen_addr = f'{self.host}:{self.port}'
            self.server.add_insecure_port(listen_addr)
            
            # Start server
            await self.server.start()
            self.logger.info(f"gRPC server started on {listen_addr}")
            
            # Wait for termination
            await self.server.wait_for_termination()
            
        except Exception as e:
            self.logger.error("Failed to start gRPC server", exc_info=True)
            raise
    
    async def stop_server(self) -> None:
        """Stop the gRPC server."""
        try:
            if self.server:
                await self.server.stop(grace=5.0)
            
            if self.detection_engine:
                await self.detection_engine.stop()
            
            self.logger.info("gRPC server stopped")
            
        except Exception as e:
            self.logger.error("Error stopping gRPC server", exc_info=True)
    
    async def DetectThreats(self, request: InferenceRequest, context) -> InferenceResponse:
        """
        Detect threats in network flows (unary RPC).
        
        Args:
            request: Inference request with network flows
            context: gRPC context
            
        Returns:
            Inference response with threat detections
        """
        start_time = datetime.utcnow()
        
        try:
            self.request_count += 1
            
            # Validate request
            if not request.flows:
                context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
                context.set_details("No flows provided for analysis")
                return InferenceResponse()
            
            # Convert request flows to NetworkFlow objects
            flows = []
            for flow_data in request.flows:
                try:
                    # This would normally use protobuf conversion
                    flow = self._convert_proto_to_network_flow(flow_data)
                    flows.append(flow)
                except Exception as e:
                    self.logger.warning(f"Failed to convert flow data: {e}")
                    continue
            
            if not flows:
                context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
                context.set_details("No valid flows found in request")
                return InferenceResponse()
            
            # Perform threat detection
            detections = await self.detection_engine.detect_threats(flows)
            
            # Calculate processing time
            processing_time = (datetime.utcnow() - start_time).total_seconds() * 1000
            
            # Create response
            response = InferenceResponse()
            response.processing_time_ms = processing_time
            response.status = "success"
            
            # Convert detections to proto format
            for detection in detections:
                proto_detection = self._convert_detection_to_proto(detection)
                response.detections.append(proto_detection)
            
            # Add models used
            if self.detection_engine.model_manager:
                response.models_used = self.detection_engine.model_manager.get_loaded_models()
            
            self.logger.info(
                f"gRPC detection completed: {len(flows)} flows, "
                f"{len(detections)} detections, {processing_time:.2f}ms"
            )
            
            return response
            
        except Exception as e:
            self.error_count += 1
            self.logger.error(f"gRPC threat detection failed: {str(e)}", exc_info=True)
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details("Internal server error during threat detection")
            return InferenceResponse()
    
    async def DetectThreatsStream(self, request_iterator, context) -> AsyncIterator[InferenceResponse]:
        """
        Detect threats in streaming network flows (streaming RPC).
        
        Args:
            request_iterator: Stream of inference requests
            context: gRPC context
            
        Yields:
            Stream of inference responses
        """
        try:
            async for request in request_iterator:
                try:
                    # Process each request
                    response = await self.DetectThreats(request, context)
                    yield response
                    
                except Exception as e:
                    self.logger.error(f"Stream processing error: {str(e)}", exc_info=True)
                    # Continue processing other requests
                    continue
                    
        except Exception as e:
            self.logger.error(f"gRPC streaming failed: {str(e)}", exc_info=True)
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details("Streaming error")
    
    async def HealthCheck(self, request: HealthRequest, context) -> HealthResponse:
        """
        Perform health check (unary RPC).
        
        Args:
            request: Health check request
            context: gRPC context
            
        Returns:
            Health check response
        """
        try:
            response = HealthResponse()
            
            # Check service health
            if self.detection_engine and self.detection_engine.is_running():
                response.status = "SERVING"
            else:
                response.status = "NOT_SERVING"
            
            response.timestamp = datetime.utcnow().isoformat()
            
            # Add health details
            if self.detection_engine:
                health_info = await self.detection_engine.health_check()
                response.details = json.dumps(health_info)
            
            return response
            
        except Exception as e:
            self.logger.error(f"gRPC health check failed: {str(e)}", exc_info=True)
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details("Health check failed")
            return HealthResponse()
    
    def _convert_proto_to_network_flow(self, proto_flow) -> NetworkFlow:
        """
        Convert protobuf flow message to NetworkFlow object.
        
        Args:
            proto_flow: Protobuf flow message
            
        Returns:
            NetworkFlow object
        """
        # This is a simplified conversion - would normally use generated protobuf code
        return NetworkFlow(
            timestamp=datetime.fromisoformat(proto_flow.timestamp.replace('Z', '+00:00')),
            source_ip=proto_flow.source_ip,
            destination_ip=proto_flow.destination_ip,
            source_port=proto_flow.source_port,
            destination_port=proto_flow.destination_port,
            protocol=proto_flow.protocol,
            bytes_sent=proto_flow.bytes_sent,
            bytes_received=proto_flow.bytes_received,
            packets_sent=proto_flow.packets_sent,
            packets_received=proto_flow.packets_received,
            duration_ms=proto_flow.duration_ms,
            inter_arrival_mean_ms=proto_flow.inter_arrival_mean_ms,
            inter_arrival_std_ms=proto_flow.inter_arrival_std_ms,
            jitter_ms=proto_flow.jitter_ms
        )
    
    def _convert_detection_to_proto(self, detection: ThreatDetection) -> Any:
        """
        Convert ThreatDetection object to protobuf message.
        
        Args:
            detection: ThreatDetection object
            
        Returns:
            Protobuf detection message
        """
        # This is a simplified conversion - would normally use generated protobuf code
        proto_detection = type('ProtoDetection', (), {})()
        
        proto_detection.detection_id = detection.detection_id
        proto_detection.timestamp = detection.timestamp.isoformat()
        proto_detection.source_flow_id = detection.source_flow_id
        proto_detection.device_id = detection.device_id
        proto_detection.threat_score = detection.threat_score
        proto_detection.confidence = detection.confidence
        proto_detection.severity = detection.severity.value
        proto_detection.attack_category = detection.attack_category.value
        
        # Convert signature matches
        proto_detection.signature_matches = []
        for match in detection.signature_matches:
            proto_match = type('ProtoSignatureMatch', (), {})()
            proto_match.rule_id = match.rule_id
            proto_match.rule_name = match.rule_name
            proto_match.signature_score = match.signature_score
            proto_detection.signature_matches.append(proto_match)
        
        # Convert ML predictions
        proto_detection.ml_predictions = []
        for pred in detection.ml_predictions:
            proto_pred = type('ProtoMLPrediction', (), {})()
            proto_pred.model_name = pred.model_name
            proto_pred.model_version = pred.model_version
            proto_pred.anomaly_score = pred.anomaly_score
            proto_pred.feature_importance = json.dumps(pred.feature_importance)
            proto_detection.ml_predictions.append(proto_pred)
        
        proto_detection.mitre_tactics = detection.mitre_tactics
        proto_detection.recommended_actions = detection.recommended_actions
        
        return proto_detection
    
    def get_service_info(self) -> Dict[str, Any]:
        """Get gRPC service information."""
        return {
            'service_name': 'InferenceService',
            'host': self.host,
            'port': self.port,
            'max_workers': self.max_workers,
            'uptime_seconds': (datetime.utcnow() - self.start_time).total_seconds(),
            'request_count': self.request_count,
            'error_count': self.error_count,
            'is_running': self.server is not None
        }


async def run_grpc_server(config: Dict[str, Any]) -> None:
    """
    Run the gRPC inference server.
    
    Args:
        config: Server configuration
    """
    service = GRPCInferenceService(config)
    
    try:
        await service.initialize()
        await service.start_server()
    except KeyboardInterrupt:
        print("Shutting down gRPC server...")
    finally:
        await service.stop_server()


if __name__ == "__main__":
    # Example configuration
    config = {
        'host': '0.0.0.0',
        'port': 50051,
        'max_workers': 10,
        'detection_engine': {
            'enable_signature_detection': True,
            'enable_ml_detection': True,
            'signature_rules': {
                'rules': [],
                'enabled_rules': []
            },
            'model_manager': {
                'default_models': []
            }
        }
    }
    
    # Run server
    asyncio.run(run_grpc_server(config))