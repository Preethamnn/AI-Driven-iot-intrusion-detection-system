# Quick Start Guide

Get the AI-Driven IoT IDS up and running in 10 minutes.

## Prerequisites

- Docker and Docker Compose installed
- 8GB+ RAM available
- Network connectivity

## Step 1: Clone Repository

```bash
git clone https://github.com/ai-iot-ids/ai-iot-ids.git
cd ai-iot-ids
```

## Step 2: Create Configuration

```bash
# Copy example configurations
cp config/edge-gateway.example.yml config/edge-gateway.yml
cp config/ai-service.example.yml config/ai-service.yml
```

## Step 3: Build Docker Images

```bash
make build-all
```

This will build:
- AI inference service container
- Edge gateway container

## Step 4: Start Services

```bash
make docker-up
```

This starts:
- Elasticsearch (data storage)
- Logstash (data processing)
- Kibana (visualization)
- AI inference service
- Edge gateway

## Step 5: Verify Deployment

**Check service health**:
```bash
# AI service
curl http://localhost:8000/health

# Elasticsearch
curl http://localhost:9200/_cluster/health
```

**View logs**:
```bash
docker-compose logs -f ai-service
```

**Access Kibana**:
Open http://localhost:5601 in your browser

## Step 6: Test Threat Detection

**Send a test flow**:
```bash
curl -X POST http://localhost:8000/api/v1/score \
  -H "Content-Type: application/json" \
  -d '{
    "flow_id": "test-001",
    "timestamp": "2024-01-15T10:30:00Z",
    "source_ip": "192.168.1.100",
    "destination_ip": "8.8.8.8",
    "source_port": 54321,
    "destination_port": 443,
    "protocol": "TCP",
    "bytes_sent": 1024,
    "bytes_received": 2048,
    "packets_sent": 10,
    "packets_received": 15,
    "duration_ms": 5000
  }'
```

**Expected response**:
```json
{
  "detection_id": "...",
  "threat_score": 0.15,
  "severity": "low",
  "confidence": 0.85
}
```

## Step 7: View Data in Kibana

1. Open http://localhost:5601
2. Navigate to "Discover"
3. Create index pattern: `iot-ids-*`
4. View threat detections and network flows

## Next Steps

- **Configure for your network**: Edit `config/edge-gateway.yml` to set your network interface
- **Deploy to production**: See [DEPLOYMENT.md](DEPLOYMENT.md) for Kubernetes deployment
- **Customize detection**: Adjust model parameters in `config/ai-service.yml`
- **Set up alerts**: Configure email/Slack notifications in configuration files

## Troubleshooting

**Services not starting**:
```bash
# Check Docker logs
docker-compose logs

# Restart services
make docker-down
make docker-up
```

**Port conflicts**:
Edit `docker-compose.yml` to change port mappings if needed.

**Memory issues**:
Reduce Elasticsearch heap size in `docker-compose.yml`:
```yaml
environment:
  - "ES_JAVA_OPTS=-Xms512m -Xmx512m"
```

## Stopping Services

```bash
make docker-down
```

## Clean Up

```bash
# Stop and remove all containers and volumes
docker-compose down -v

# Remove Docker images
docker rmi iot-ids/ai-service:latest
docker rmi iot-ids/edge-gateway:latest
```

## Getting Help

- Read the [full documentation](../README.md)
- Check [DEPLOYMENT.md](DEPLOYMENT.md) for detailed instructions
- Review [CONFIGURATION.md](CONFIGURATION.md) for configuration options
- Open an issue on GitHub
