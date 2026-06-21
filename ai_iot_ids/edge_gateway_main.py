"""
Main application entry point for Edge Gateway.

This module provides the main application that runs on Raspberry Pi devices
to perform packet capture, protocol decoding, feature extraction, and secure
forwarding to upstream AI inference services.
"""

import asyncio
import logging
import signal
import sys
from typing import Dict, Any, Optional, List
from pathlib import Path
import argparse
from datetime import datetime

from .utils.logging_config import setup_logging
from .utils.config_parser import ConfigurationManager, YAMLConfigParser
from .utils.error_handling import IDSError, ErrorSeverity
from .models.system_configuration import SystemConfiguration
from .integration.component_factory import ComponentFactory
from .integration.system_orchestrator import SystemOrchestrator


class EdgeGatewayApp:
    """
    Main application for Edge Gateway running on Raspberry Pi devices.
    
    Uses the system orchestrator to manage all components and data flow
    from packet capture through feature extraction to secure forwarding.
    """
    
    def __init__(self, config: SystemConfiguration, logger=None):
        """
        Initialize the edge gateway application.
        
        Args:
            config: System configuration object
            logger: Optional logger instance
        """
        self.config = config
        self.logger = logger or logging.getLogger(__name__)
        
        # Component factory and orchestrator
        self.component_factory = ComponentFactory(config, self.logger)
        self.orchestrator: Optional[SystemOrchestrator] = None
        self.components: Optional[Dict[str, Any]] = None
        
        # Application state
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
    
    async def initialize(self) -> None:
        """Initialize all edge gateway components using the orchestrator."""
        try:
            self.logger.info("Initializing Edge Gateway components...")
            
            # Create orchestrator and all components
            self.orchestrator, self.components = self.component_factory.create_system_orchestrator()
            
            # Initialize all components
            await self.component_factory.initialize_all_components(self.components)
            
            # Start all components
            await self.component_factory.start_all_components(self.components)
            
            self.logger.info("All Edge Gateway components initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize Edge Gateway: {e}", exc_info=True)
            raise IDSError(f"Edge Gateway initialization failed: {e}")
    
    async def start(self) -> None:
        """Start the edge gateway application."""
        try:
            self.logger.info("Starting Edge Gateway application...")
            
            # Initialize components if not already done
            if not self.orchestrator:
                await self.initialize()
            
            # Start packet capture on configured interface
            interface = self.config.edge_gateway.packet_capture.interface
            filter_expr = self.config.edge_gateway.packet_capture.capture_filter
            
            packet_capture = self.components['packet_capture']
            await packet_capture.start_capture(interface, filter_expr)
            self.logger.info(f"Started packet capture on interface '{interface}'")
            
            # Start the system orchestrator (this runs all processing pipelines)
            await asyncio.gather(
                self.orchestrator.start(),
                self.shutdown_event.wait()
            )
            
        except Exception as e:
            self.logger.error(f"Edge Gateway application failed: {e}", exc_info=True)
            raise
    
    async def _shutdown(self) -> None:
        """Perform graceful shutdown of all components."""
        try:
            self.logger.info("Shutting down Edge Gateway...")
            
            # Stop the orchestrator (this stops all processing pipelines)
            if self.orchestrator:
                await self.orchestrator.stop()
            
            # Stop all components
            if self.components:
                await self.component_factory.stop_all_components(self.components)
            
            # Signal shutdown completion
            self.shutdown_event.set()
            
            self.logger.info("Edge Gateway shutdown completed")
            
        except Exception as e:
            self.logger.error(f"Error during shutdown: {e}", exc_info=True)


def load_configuration(config_path: Optional[str] = None) -> SystemConfiguration:
    """
    Load system configuration from file or use defaults.
    
    Args:
        config_path: Optional path to configuration file
        
    Returns:
        SystemConfiguration object
    """
    if config_path:
        config_file = Path(config_path)
        if not config_file.exists():
            raise FileNotFoundError(f"Configuration file not found: {config_path}")
        
        parser = YAMLConfigParser()
        manager = ConfigurationManager(parser)
        return manager.load_configuration(config_file)
    else:
        # Return default configuration for edge gateway
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
                    'upstream_endpoints': ['https://ai-service:8080/api/v1/ingest'],
                    'batch_size': 100,
                    'flush_interval_ms': 5000,
                    'retry_attempts': 3
                }
            },
            storage={
                'elasticsearch': {
                    'hosts': ['http://elasticsearch:9200'],
                    'index_prefix': 'iot-ids',
                    'shard_count': 1,
                    'replica_count': 1
                }
            },
            inference={
                'default_models': [
                    {
                        'name': 'isolation_forest_v1',
                        'type': 'unsupervised',
                        'model_version': '1.0.0',
                        'contamination': 0.05,
                        'model_path': 'models/artifacts/isolation_forest_v1.pkl'
                    }
                ]
            }
        )


async def main():
    """Main application entry point."""
    parser = argparse.ArgumentParser(description='AI-Driven IoT IDS Edge Gateway')
    parser.add_argument(
        '--config', '-c',
        type=str,
        help='Path to configuration file (YAML)'
    )
    parser.add_argument(
        '--interface', '-i',
        type=str,
        help='Network interface for packet capture'
    )
    parser.add_argument(
        '--filter', '-f',
        type=str,
        help='BPF filter expression for packet capture'
    )
    parser.add_argument(
        '--log-level',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
        default='INFO',
        help='Set logging level'
    )
    parser.add_argument(
        '--upstream',
        type=str,
        action='append',
        help='Upstream endpoint URL (can be specified multiple times)'
    )
    
    args = parser.parse_args()
    
    try:
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
                    'formatter': 'standard'
                }
            },
            'root': {
                'level': args.log_level,
                'handlers': ['console']
            }
        }
        setup_logging(logging_config)
        logger = logging.getLogger(__name__)
        
        # Load configuration
        config = load_configuration(args.config)
        
        # Apply command line overrides
        if args.interface:
            config.edge_gateway.packet_capture.interface = args.interface
        
        if args.filter:
            config.edge_gateway.packet_capture.capture_filter = args.filter
        
        if args.upstream:
            config.edge_gateway.forwarding.upstream_endpoints = args.upstream
        
        # Validate configuration
        config.validate_configuration()
        
        logger.info("Starting AI-Driven IoT IDS Edge Gateway")
        logger.info(f"Interface: {config.edge_gateway.packet_capture.interface}")
        logger.info(f"Upstream endpoints: {config.edge_gateway.forwarding.upstream_endpoints}")
        
        # Create and start application
        app = EdgeGatewayApp(config, logger)
        await app.start()
        
    except KeyboardInterrupt:
        print("\nShutdown requested by user")
    except Exception as e:
        print(f"Edge Gateway failed: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())