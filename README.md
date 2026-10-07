# AI-Driven IoT Intrusion Detection System

<div align="center">

[![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?logo=docker&logoColor=white)](https://www.docker.com/)
[![Security](https://img.shields.io/badge/Security-Hybrid%20ML%20%2B%20Rules-red)](https://github.com/Preethamnn/AI-Driven-iot-intrusion-detection-system)

</div>

<p align="center">
  <img src="https://img.shields.io/badge/IoT-Security-0A84FF?style=for-the-badge" alt="IoT Security" />
  <img src="https://img.shields.io/badge/AI-Anomaly%20Detection-7C3AED?style=for-the-badge" alt="AI Anomaly Detection" />
  <img src="https://img.shields.io/badge/Network-Threat%20Monitoring-FF6B6B?style=for-the-badge" alt="Threat Monitoring" />
</p>

A multi-layered security platform designed to monitor and protect IoT and industrial control networks through hybrid threat detection that combines signature-based rules with machine learning-based anomaly detection.

## Overview

This project delivers a modern intrusion detection architecture for connected devices and SCADA/ICS environments. It blends:

- Signature-based detection via Suricata and Zeek
- ML-driven anomaly detection for behavioral deviations
- Edge-based packet capture and preprocessing
- Centralized inference and observability
- Secure communication for distributed deployment

The result is a scalable, production-oriented security solution for device profiling, network monitoring, risk scoring, and rapid incident response.

## Why this system?

IoT and industrial networks often face threats that are difficult to detect with static rules alone. This project helps organizations detect both:

- Known malicious patterns and signatures
- Unknown or evolving device behavior anomalies

By combining rule-based detection with AI-assisted learning, the system improves detection accuracy while maintaining real-time visibility.

## Key Features

<div align="center">

| Capability | Description |
| --- | --- |
| Hybrid Threat Detection | Combines signature-based rules with ML-based anomaly detection |
| Real-Time Processing | Low-latency packet capture and analysis for immediate remediation |
| Device Profiling | Creates behavioral baselines for individual IoT devices |
| Scalable Architecture | Supports distributed edge gateways and centralized AI inference |
| Observability | Elasticsearch + Kibana provide analytics and dashboards |
| MLOps Integration | Supports model lifecycle management and deployment automation |

</div>

## Architecture

The system is organized into layered components:

- Edge Layer: Raspberry Pi gateways for local packet capture and preprocessing
- Transport Layer: Secure mTLS communication between services
- AI Layer: Containerized inference for ML-based threat detection
- Storage Layer: Elasticsearch-based persistence and visualization
- Operations Layer: MLOps pipelines for model lifecycle and drift management

```text
┌──────────────────────────────────────────────────────────────────┐
│                       IoT / ICS Environment                      │
└───────────────────────────────┬──────────────────────────────────┘
                                │
                                ▼
┌──────────────────────────────────────────────────────────────────┐
│                    Edge Gateway Layer (Raspberry Pi)            │
│  Packet capture  │  Protocol decode  │  Preprocessing          │
└───────────────────────────────┬──────────────────────────────────┘
                                │
                                ▼
┌──────────────────────────────────────────────────────────────────┐
│                    Secure Transport Layer                       │
│                      mTLS / Event Forwarding                     │
└───────────────────────────────┬──────────────────────────────────┘
                                │
                                ▼
┌──────────────────────────────────────────────────────────────────┐
│                       AI Inference Layer                        │
│ Signature scoring │ ML anomaly detection │ Decision engine     │
└───────────────────────────────┬──────────────────────────────────┘
                                │
                                ▼
┌──────────────────────────────────────────────────────────────────┐
│                       Storage & Observability                   │
│  Elasticsearch │ Kibana │ Alerting │ Metrics                   │
└──────────────────────────────────────────────────────────────────┘
```

## Installation

### Prerequisites

- Python 3.11+
- Docker 20.10+ and Docker Compose 2.0+
- Kubernetes 1.24+ for production deployments
- Network interface access for packet capture (requires NET_ADMIN and NET_RAW)

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

Create configuration files from the examples:

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

See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) for detailed deployment procedures.

## Configuration

The system uses YAML configuration files with the following primary sections:

- `edge_gateway`: Packet capture and protocol decoding settings
- `ai_inference`: ML model configuration and feature engineering
- `storage`: Elasticsearch and retention policies
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

The system uses Pydantic models for validation and serialization:

- `NetworkFlow`: Network traffic features for ML analysis
- `DeviceProfile`: Behavioral baselines for individual IoT devices
- `ThreatDetection`: Security threats identified by the hybrid engine
- `SystemConfiguration`: Complete validated system configuration

## Testing

The project includes comprehensive test coverage across several categories:

- Unit tests for component-level behavior
- Property-based tests for invariant validation
- Integration tests for end-to-end behavior

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

- Black for code formatting
- isort for import sorting
- mypy for type checking
- flake8 for linting

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

```text
ai_iot_ids/
├── models/              # Pydantic data models
├── interfaces/          # Abstract base classes
├── utils/               # Logging, error handling, config parsing
├── edge/                # Edge gateway components
├── inference/           # AI inference service
├── transport/           # Secure communication
├── observability/       # Monitoring and alerting
└── ...

tests/
├── unit/                # Unit tests
├── integration/         # Integration tests
├── property/            # Property-based tests
└── ...
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

- mTLS: Encryption between components
- Certificate Rotation: Automated certificate lifecycle management
- Network Segmentation: VLAN isolation for device classes
- Container Security: Read-only filesystems and non-root execution
- Access Controls: AppArmor/SELinux enforcement

## Performance

Performance characteristics:

- Packet Processing: Up to 10,000 packets/second per edge gateway
- ML Inference: Sub-100ms latency for threat scoring
- Memory Usage: Bounded queues prevent exhaustion
- Scalability: Horizontal scaling through container orchestration

## Documentation

- [Deployment Guide](docs/DEPLOYMENT.md)
- [Operations Guide](docs/OPERATIONS.md)
- [API Documentation](docs/API.md)
- [Configuration Guide](docs/CONFIGURATION.md)

## API Reference

The AI service provides REST and gRPC APIs for threat detection.

### REST API

```bash
# Health check
curl http://ai-service:8000/health

# Score a network flow
curl -X POST http://ai-service:8000/api/v1/score \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d @flow.json
```

### gRPC API

```python
import grpc
from ai_iot_ids.inference.api import threat_detection_pb2_grpc

channel = grpc.insecure_channel('ai-service:50051')
stub = threat_detection_pb2_grpc.ThreatDetectionStub(channel)
response = stub.ScoreFlow(request)
```

See [docs/API.md](docs/API.md) for complete API documentation.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make changes with tests
4. Run the test suite
5. Submit a pull request

## Support

- Documentation: [docs/](docs/)
- Issues: [GitHub Issues](https://github.com/ai-iot-ids/ai-iot-ids/issues)
- Discussions: [GitHub Discussions](https://github.com/ai-iot-ids/ai-iot-ids/discussions)

## Acknowledgments

- Zeek: Network security monitoring framework
- Suricata: Intrusion detection system
- Elasticsearch: Search and analytics engine
- scikit-learn: Machine learning library
- Pydantic: Data validation via Python type annotations

<div align="center">

Built for secure, intelligent IoT network defense.

</div>
