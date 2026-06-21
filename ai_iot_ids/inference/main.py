"""
Main application entry point for AI inference service.

This module provides the main application that can run both REST API
and gRPC services for threat detection inference.
"""

import asyncio
import logging
import signal
import sys
from typing import Dict, Any, Optional
from pathlib import Path
import json
import argparse

try:
    import uvicorn
    UVICORN_AVAILABLE = True
except ImportError:
    UVICORN_AVAILABLE = False

from .api.rest_api import create_app
from .api.grpc_service import GRPCInferenceService
from ..utils.logging_config import setup_logging
from ..utils.config_parser import ConfigurationManager, YAMLConfigParser
from ..models.system_configuration import SystemConfiguration


class InferenceServiceApp:
    """
    Main application for AI inference service.
    
    Manages both REST API and gRPC services with graceful shutdown
    and configuration management.
    """
    
    def __init__(self, config: SystemConfiguration):
        """
        Initialize the inference service application.
        
        Args:
            config: System configuration object
        """
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Service configuration
        self.enable_rest_api = True  # Always enable REST API for inference service
        self.enable_grpc_service = False  # Optional gRPC service
        
        # Service instances
        self.rest_app = None
        self.grpc_service = None
        self.uvicorn_server = None
        
        # Shutdown event
        self.shutdown_event = asyncio.Event()
        
        # Setup signal handlers
        self._setup_signal_handlers()
    
    def _setup_signal_handlers(self):
        """Setup signal handlers for graceful shutdown."""
        def signal_handler(signum, frame):
            self.logger.info(f"Received signal {signum}, initiating shutdown...")
            asyncio.create_task(self._shutdown())
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
    
    async def start(self):
        """Start the inference service application."""
        try:
            self.logger.info("Starting AI Inference Service...")
            
            # Start services concurrently
            tasks = []
            
            if self.enable_rest_api:
                tasks.append(self._start_rest_api())
            
            if self.enable_grpc_service:
                tasks.append(self._start_grpc_service())
            
            if not tasks:
                raise RuntimeError("No services enabled. Enable at least one of REST API or gRPC service.")
            
            # Wait for shutdown signal
            await asyncio.gather(*tasks, self.shutdown_event.wait())
            
        except Exception as e:
            self.logger.error(f"Failed to start inference service: {e}", exc_info=True)
            raise
    
    async def _start_rest_api(self):
        """Start the REST API service."""
        try:
            if not UVICORN_AVAILABLE:
                raise ImportError("uvicorn is required for REST API. Install with: pip install uvicorn")
            
            # Create FastAPI app with AI inference configuration
            rest_config = {
                'enable_cors': True,
                'enable_gzip': True,
                'detection_engine': {
                    'enable_signature_detection': True,
                    'enable_ml_detection': True,
                    'signature_rules': {
                        'rules': [],
                        'enabled_rules': []
                    },
                    'score_calculation': {
                        'signature_weight': self.config.ai_inference.decision_engine.signature_weight,
                        'ml_weight': self.config.ai_inference.decision_engine.ml_weight,
                        'threshold_low': self.config.ai_inference.decision_engine.threshold_low,
                        'threshold_high': self.config.ai_inference.decision_engine.threshold_high
                    },
                    'model_manager': {
                        'model_base_path': 'models/',
                        'default_models': [{'name': m} for m in self.config.get_enabled_models()]
                    }
                }
            }
            self.rest_app = create_app(rest_config)
            
            # Configure uvicorn
            uvicorn_config = uvicorn.Config(
                app=self.rest_app,
                host='0.0.0.0',
                port=8000,
                log_level='info',
                access_log=True,
                reload=False,
                workers=1  # Single worker for async app
            )
            
            # Create and start server
            self.uvicorn_server = uvicorn.Server(uvicorn_config)
            
            self.logger.info(f"Starting REST API on {uvicorn_config.host}:{uvicorn_config.port}")
            await self.uvicorn_server.serve()
            
        except Exception as e:
            self.logger.error(f"REST API service failed: {e}", exc_info=True)
            raise
    
    async def _start_grpc_service(self):
        """Start the gRPC service."""
        try:
            grpc_config = {
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
                        'default_models': [{'name': m} for m in self.config.get_enabled_models()]
                    }
                }
            }
            self.grpc_service = GRPCInferenceService(grpc_config, self.logger)
            
            await self.grpc_service.initialize()
            
            self.logger.info(f"Starting gRPC service on 0.0.0.0:50051")
            await self.grpc_service.start_server()
            
        except Exception as e:
            self.logger.error(f"gRPC service failed: {e}", exc_info=True)
            raise
    
    async def _shutdown(self):
        """Perform graceful shutdown of all services."""
        try:
            self.logger.info("Shutting down inference service...")
            
            # Stop REST API
            if self.uvicorn_server:
                self.uvicorn_server.should_exit = True
                await self.uvicorn_server.shutdown()
            
            # Stop gRPC service
            if self.grpc_service:
                await self.grpc_service.stop_server()
            
            # Signal shutdown completion
            self.shutdown_event.set()
            
            self.logger.info("Inference service shutdown completed")
            
        except Exception as e:
            self.logger.error(f"Error during shutdown: {e}", exc_info=True)


def load_config(config_path: str) -> SystemConfiguration:
    """
    Load configuration from file.
    
    Args:
        config_path: Path to configuration file
        
    Returns:
        SystemConfiguration object
    """
    config_file = Path(config_path)
    
    if not config_file.exists():
        raise FileNotFoundError(f"Configuration file not found: {config_path}")
    
    parser = YAMLConfigParser()
    manager = ConfigurationManager(parser)
    return manager.load_configuration(config_file)


def get_default_config() -> SystemConfiguration:
    """
    Get default configuration.
    
    Returns:
        Default SystemConfiguration object
    """
    return SystemConfiguration(
        edge_gateway={
            'packet_capture': {
                'interface': 'eth0',
                'buffer_size_mb': 64,
                'capture_filter': ''
            },
            'protocol_decoders': {
                'zeek_enabled': True,
                'suricata_enabled': True,
                'custom_rules_path': '/etc/ids/rules'
            },
            'forwarding': {
                'upstream_endpoints': ['http://localhost:8000/api/v1/ingest'],
                'batch_size': 100,
                'flush_interval_ms': 5000,
                'retry_attempts': 3
            }
        },
        ai_inference={
            'models': {
                'isolation_forest': {
                    'enabled': True,
                    'contamination': 0.1,
                    'n_estimators': 100
                },
                'xgboost': {
                    'enabled': True,
                    'max_depth': 6,
                    'learning_rate': 0.1,
                    'n_estimators': 100
                }
            },
            'feature_engineering': {
                'time_window_minutes': 5,
                'aggregation_functions': ['mean', 'std', 'max']
            },
            'decision_engine': {
                'signature_weight': 0.6,
                'ml_weight': 0.4,
                'threshold_low': 0.3,
                'threshold_high': 0.7
            }
        },
        storage={
            'elasticsearch': {
                'hosts': ['http://elasticsearch:9200'],
                'index_prefix': 'iot-ids',
                'shard_count': 1,
                'replica_count': 1
            }
        }
    )


async def main():
    """Main application entry point."""
    parser = argparse.ArgumentParser(description='AI-Driven IoT IDS Inference Service')
    parser.add_argument(
        '--config', '-c',
        type=str,
        help='Path to configuration file (JSON or YAML)'
    )
    parser.add_argument(
        '--rest-only',
        action='store_true',
        help='Run only REST API service'
    )
    parser.add_argument(
        '--grpc-only',
        action='store_true',
        help='Run only gRPC service'
    )
    parser.add_argument(
        '--port',
        type=int,
        help='Override REST API port'
    )
    parser.add_argument(
        '--grpc-port',
        type=int,
        help='Override gRPC service port'
    )
    parser.add_argument(
        '--log-level',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
        default='INFO',
        help='Set logging level'
    )
    
    args = parser.parse_args()
    
    try:
        # Load configuration
        if args.config:
            config = load_config(args.config)
        else:
            config = get_default_config()
        
        # Apply command line overrides
        if args.rest_only:
            # REST-only mode (default for inference service)
            pass
        elif args.grpc_only:
            # gRPC-only mode (not recommended for inference service)
            pass
        
        if args.port:
            # Port override would need to be handled in uvicorn config
            pass
        
        if args.grpc_port:
            # gRPC port override would need to be handled in gRPC config
            pass
        
        # Setup logging
        logging_config = {
            'version': 1,
            'disable_existing_loggers': False,
            'formatters': {
                'standard': {
                    'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
                }
            },
            'handlers': {
                'console': {
                    'class': 'logging.StreamHandler',
                    'level': args.log_level,
                    'formatter': 'standard',
                    'stream': 'ext://sys.stdout'
                }
            },
            'root': {
                'level': args.log_level,
                'handlers': ['console']
            }
        }
        setup_logging(logging_config)
        
        # Create and start application
        app = InferenceServiceApp(config)
        await app.start()
        
    except KeyboardInterrupt:
        print("\nShutdown requested by user")
    except Exception as e:
        print(f"Application failed: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())