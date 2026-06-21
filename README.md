# AI-Driven IoT Intrusion Detection System

A multi-layered security solution designed to monitor and protect IoT/ICS networks through hybrid detection combining signature-based rules with machine learning-based anomaly detection.

## Features

- **Hybrid Threat Detection**: Combines signature-based rules (Suricata/Zeek) with ML-based anomaly detection
- **Real-time Processing**: Low-latency packet capture and analysis for immediate threat response
- **Device Profiling**: Behavioral baselines for individual IoT devices with anomaly detection
- **Scalable Architecture**: Distributed edge gateways with centralized AI inference services
- **Comprehensive Observability**: Elasticsearch-based storage with Kibana dashboards
- **MLOps Integration**: Automated model lifecycle management and deployment

## Architecture

The system follows a layered architecture:

- **Edge Layer**: Raspberry Pi gateways for local packet capture and preprocessing
- **Transport Layer**: Secure mTLS communication between components
- **AI Layer**: Containerized inference services with ML-based threat detection
- **Storage Layer**: Elasticsearch stack for data persistence and visualization
- **Operations Layer**: MLOps pipelines for model management and deployment

## Installation

### Prerequisites

- Python 3.11 or higher
- Docker 20.10+ and Docker Compose 2.0+ (for containerized deployment)
- Kubernetes 1.24+ (for production deployment)
- Network interface access for packet capture (requires NET_ADMIN and NET_RAW capabilities)

### Basic Installation

```bash
# Clone the repository
git clone https://github.com/ai-iot-ids/ai-iot-ids.git
cd ai-iot-ids

# Install dependencies
pip install -r requirements.txt

# Install the package
pip install -e .
```

### Development Installation

```bash
# Install with development dependencies
pip install -e ".[dev]"

# Run tests to verify installation
pytest
```

## Quick Start

### 1. Configuration

Create configuration files based on the examples:

```bash
# Copy example configurations
cp config/edge-gateway.example.yml config/edge-gateway.yml
cp config/ai-service.example.yml config/ai-service.yml

# Edit configurations for your environment
vim config/edge-gateway.yml
vim config/ai-service.yml
```

### 2. Local Development with Docker Compose

```bash
# Build Docker images
make build-all

# Start all services
make docker-up

# Check service status
docker-compose ps

# View logs
docker-compose logs -f

# Access Kibana dashboard
open http://localhost:5601

# Stop services
make docker-down
```

### 3. Run Tests

```bash
# Run all tests
pytest

# Run property-based tests
pytest tests/test_property_config_roundtrip.py

# Run with coverage
pytest --cov=ai_iot_ids --cov-report=html
```

### 4. Production Deployment

See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) for detailed deployment instructions.

## Configuration

The system uses YAML configuration files with the following main sections:

- `edge_gateway`: Packet capture and protocol decoding settings
- `ai_inference`: ML model configuration and feature engineering
- `storage`: Elasticsearch and data retention settings
- `security`: TLS/mTLS and authentication settings
- `mlops`: Model registry and drift monitoring

Example configuration:

```yaml
edge_gateway:
  packet_capture:
    interface: eth0
    buffer_size_mb: 64
    capture_filter: ""
  
  protocol_decoders:
    zeek_enabled: true
    suricata_enabled: true
    custom_rules_path: "/app/config/rules"
  
  forwarding:
    upstream_endpoints:
      - "http://ai-service:8000"
    batch_size: 100
    flush_interval_ms: 1000

ai_inference:
  models:
    isolation_forest:
      enabled: true
      contamination: 0.1
      n_estimators: 100
    
    xgboost:
      enabled: true
      max_depth: 6
      learning_rate: 0.1
  
  decision_engine:
    signature_weight: 0.6
    ml_weight: 0.4
    threshold_high: 0.7

storage:
  elasticsearch:
    hosts: ["http://elasticsearch:9200"]
    index_prefix: "iot-ids"
    shard_count: 3
    replica_count: 1
  
  retention:
    raw_data_days: 7
    aggregated_data_days: 30
    alert_data_days: 90
```

For complete configuration options, see [docs/CONFIGURATION.md](docs/CONFIGURATION.md).

## Data Models

The system uses Pydantic models for data validation and serialization:

- **NetworkFlow**: Network traffic flow features for ML analysis
- **DeviceProfile**: Behavioral baselines for individual IoT devices
- **ThreatDetection**: Security threats detected by the hybrid engine
- **SystemConfiguration**: Complete system configuration with validation

## Testing

The project includes comprehensive testing:

- **Unit Tests**: Component-specific functionality testing
- **Property-Based Tests**: Universal correctness properties using Hypothesis
- **Integration Tests**: End-to-end system behavior validation

Run specific test categories:

```bash
# Unit tests only
pytest -m unit

# Property-based tests
pytest -m property

# Integration tests
pytest -m integration
```

## Development

### Code Style

The project uses:
- **Black** for code formatting
- **isort** for import sorting
- **mypy** for type checking
- **flake8** for linting

```bash
# Format code
black ai_iot_ids tests

# Sort imports
isort ai_iot_ids tests

# Type checking
mypy ai_iot_ids

# Linting
flake8 ai_iot_ids tests
```

### Project Structure

```
ai_iot_ids/
├── models/              # Pydantic data models
├── interfaces/          # Abstract base classes
├── utils/              # Logging, error handling, config parsing
├── edge/               # Edge gateway components
├── inference/          # AI inference service
├── transport/          # Secure communication
└── observability/      # Monitoring and alerting

tests/
├── unit/               # Unit tests
├── integration/        # Integration tests
└── property/           # Property-based tests
```

## Deployment

### Docker Compose (Local Development)

```bash
# Build and start all services
make build-all
make docker-up

# Check service health
curl http://localhost:8000/health

# Access Kibana
open http://localhost:5601

# Stop services
make docker-down
```

### Kubernetes (Production)

```bash
# Deploy to Kubernetes
make k8s-deploy

# Check deployment status
kubectl get all -n iot-ids

# View logs
kubectl logs -f deployment/ai-service -n iot-ids

# Remove deployment
make k8s-delete
```

### Raspberry Pi Edge Gateway

```bash
# Pull edge gateway image
docker pull iot-ids/edge-gateway:latest

# Run on Raspberry Pi
docker run -d \
  --name edge-gateway \
  --network host \
  --cap-add NET_ADMIN \
  --cap-add NET_RAW \
  -v /opt/iot-ids/config:/app/config:ro \
  -v /opt/iot-ids/data:/app/data \
  --restart unless-stopped \
  iot-ids/edge-gateway:latest
```

For detailed deployment instructions, see [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).

## Security

The system implements multiple security layers:

- **mTLS**: Encrypted communication between all components
- **Certificate Rotation**: Automatic certificate management
- **Network Segmentation**: VLAN isolation for device classes
- **Container Security**: Read-only filesystems and non-root execution
- **Access Controls**: AppArmor/SELinux mandatory access controls

## Performance

Performance characteristics:

- **Packet Processing**: Up to 10,000 packets/second per edge gateway
- **ML Inference**: Sub-100ms latency for threat scoring
- **Memory Usage**: Bounded queues prevent memory exhaustion
- **Scalability**: Horizontal scaling through container orchestration

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make changes with tests
4. Run the test suite
5. Submit a pull request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Documentation

- **[Deployment Guide](docs/DEPLOYMENT.md)**: Complete deployment instructions for Docker and Kubernetes
- **[Operations Guide](docs/OPERATIONS.md)**: Day-to-day operations, monitoring, and maintenance
- **[API Documentation](docs/API.md)**: REST and gRPC API reference
- **[Configuration Guide](docs/CONFIGURATION.md)**: Detailed configuration options

## API Reference

The AI service provides REST and gRPC APIs for threat detection:

**REST API**:
```bash
# Health check
curl http://ai-service:8000/health

# Score a network flow
curl -X POST http://ai-service:8000/api/v1/score \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d @flow.json
```

**gRPC API**:
```python
import grpc
from ai_iot_ids.inference.api import threat_detection_pb2_grpc

channel = grpc.insecure_channel('ai-service:50051')
stub = threat_detection_pb2_grpc.ThreatDetectionStub(channel)
response = stub.ScoreFlow(request)
```

See [docs/API.md](docs/API.md) for complete API documentation.

## Support

- **Documentation**: [docs/](docs/)
- **Issues**: [GitHub Issues](https://github.com/ai-iot-ids/ai-iot-ids/issues)
- **Discussions**: [GitHub Discussions](https://github.com/ai-iot-ids/ai-iot-ids/discussions)

## Acknowledgments

- **Zeek**: Network security monitoring framework
- **Suricata**: Intrusion detection system
- **Elasticsearch**: Search and analytics engine
- **scikit-learn**: Machine learning library
- **Pydantic**: Data validation using Python type annotations