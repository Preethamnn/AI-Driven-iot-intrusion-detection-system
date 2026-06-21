# Deployment Guide

This guide covers deploying the AI-Driven IoT IDS in various environments.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Local Development Deployment](#local-development-deployment)
- [Production Kubernetes Deployment](#production-kubernetes-deployment)
- [Edge Gateway Deployment](#edge-gateway-deployment)
- [Configuration](#configuration)
- [Troubleshooting](#troubleshooting)

## Prerequisites

### Software Requirements

- Docker 20.10+ and Docker Compose 2.0+
- Kubernetes 1.24+ (for production deployment)
- kubectl CLI tool
- Python 3.11+ (for local development)
- Make (optional, for convenience commands)

### Hardware Requirements

**Edge Gateway (Raspberry Pi)**:
- Raspberry Pi 4 Model B (4GB+ RAM recommended)
- 32GB+ microSD card
- Network connectivity (Ethernet recommended)

**AI Inference Service**:
- 4+ CPU cores
- 8GB+ RAM
- 50GB+ storage
- GPU optional (for deep learning models)

**Elasticsearch Cluster**:
- 3+ nodes for production
- 8GB+ RAM per node
- 100GB+ storage per node

## Local Development Deployment

### Quick Start with Docker Compose

1. **Clone the repository**:
```bash
git clone https://github.com/your-org/ai-iot-ids.git
cd ai-iot-ids
```

2. **Create configuration files**:
```bash
cp config/edge-gateway.example.yml config/edge-gateway.yml
cp config/ai-service.example.yml config/ai-service.yml
```

3. **Build Docker images**:
```bash
make build-all
# Or manually:
# docker build -f Dockerfile.ai-service -t iot-ids/ai-service:latest .
# docker build -f Dockerfile.edge-gateway -t iot-ids/edge-gateway:latest .
```

4. **Start the services**:
```bash
make docker-up
# Or manually:
# docker-compose up -d
```

5. **Verify deployment**:
```bash
# Check service status
docker-compose ps

# View logs
docker-compose logs -f

# Check AI service health
curl http://localhost:8000/health

# Access Kibana
open http://localhost:5601
```

6. **Stop the services**:
```bash
make docker-down
```

### Local Python Development

For development without Docker:

1. **Install dependencies**:
```bash
pip install -r requirements.txt
```

2. **Run AI service**:
```bash
python -m ai_iot_ids.inference.main
```

3. **Run edge gateway** (requires root for packet capture):
```bash
sudo python -m ai_iot_ids.edge_gateway_main
```

## Production Kubernetes Deployment

### Prerequisites

- Kubernetes cluster with 3+ nodes
- kubectl configured to access the cluster
- Persistent storage provisioner
- Ingress controller (nginx recommended)
- cert-manager for TLS certificates (optional)

### Deployment Steps

1. **Create namespace**:
```bash
kubectl apply -f k8s/namespace.yaml
```

2. **Configure settings**:

Edit `k8s/configmaps.yaml` to customize:
- Elasticsearch connection settings
- Model parameters
- Detection thresholds
- Resource limits

3. **Deploy storage layer**:
```bash
kubectl apply -f k8s/persistent-volumes.yaml
kubectl apply -f k8s/elasticsearch-statefulset.yaml
```

Wait for Elasticsearch to be ready:
```bash
kubectl wait --for=condition=ready pod -l app=elasticsearch -n iot-ids --timeout=300s
```

4. **Deploy AI service**:
```bash
kubectl apply -f k8s/configmaps.yaml
kubectl apply -f k8s/ai-service-deployment.yaml
```

5. **Deploy edge gateways**:
```bash
kubectl apply -f k8s/edge-gateway-daemonset.yaml
```

6. **Apply network policies**:
```bash
kubectl apply -f k8s/network-policies.yaml
```

7. **Configure ingress** (optional):

Edit `k8s/ingress.yaml` to set your domain names, then:
```bash
kubectl apply -f k8s/ingress.yaml
```

8. **Verify deployment**:
```bash
# Check all resources
kubectl get all -n iot-ids

# Check pod status
kubectl get pods -n iot-ids

# View logs
kubectl logs -f deployment/ai-service -n iot-ids

# Check service endpoints
kubectl get svc -n iot-ids
```

### Scaling

**Scale AI service horizontally**:
```bash
kubectl scale deployment ai-service --replicas=5 -n iot-ids
```

**Scale Elasticsearch cluster**:
```bash
kubectl scale statefulset elasticsearch --replicas=5 -n iot-ids
```

### Updating

**Rolling update for AI service**:
```bash
# Update image
kubectl set image deployment/ai-service ai-service=iot-ids/ai-service:v2.0 -n iot-ids

# Monitor rollout
kubectl rollout status deployment/ai-service -n iot-ids

# Rollback if needed
kubectl rollout undo deployment/ai-service -n iot-ids
```

## Edge Gateway Deployment

### Raspberry Pi Setup

1. **Install Raspberry Pi OS**:
- Use Raspberry Pi Imager
- Choose Raspberry Pi OS Lite (64-bit)
- Configure SSH and network settings

2. **Install Docker**:
```bash
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER
```

3. **Deploy edge gateway**:
```bash
# Pull image
docker pull iot-ids/edge-gateway:latest

# Create configuration
mkdir -p /opt/iot-ids/config
cp config/edge-gateway.example.yml /opt/iot-ids/config/edge-gateway.yml

# Edit configuration
nano /opt/iot-ids/config/edge-gateway.yml

# Run container
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

4. **Configure as systemd service**:

Create `/etc/systemd/system/iot-ids-edge.service`:
```ini
[Unit]
Description=IoT IDS Edge Gateway
After=docker.service
Requires=docker.service

[Service]
Type=simple
ExecStart=/usr/bin/docker start -a edge-gateway
ExecStop=/usr/bin/docker stop edge-gateway
Restart=always

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl enable iot-ids-edge
sudo systemctl start iot-ids-edge
```

## Configuration

### Environment Variables

**AI Service**:
- `CONFIG_PATH`: Path to configuration file
- `MODEL_PATH`: Path to ML models directory
- `ELASTICSEARCH_HOST`: Elasticsearch connection URL
- `LOG_LEVEL`: Logging level (DEBUG, INFO, WARNING, ERROR)

**Edge Gateway**:
- `CONFIG_PATH`: Path to configuration file
- `AI_SERVICE_URL`: AI service endpoint URL
- `LOGSTASH_HOST`: Logstash endpoint
- `INTERFACE`: Network interface to monitor

### TLS Certificates

Generate self-signed certificates for testing:
```bash
# Create CA
openssl genrsa -out ca.key 4096
openssl req -new -x509 -days 365 -key ca.key -out ca.crt

# Create server certificate
openssl genrsa -out server.key 4096
openssl req -new -key server.key -out server.csr
openssl x509 -req -days 365 -in server.csr -CA ca.crt -CAkey ca.key -set_serial 01 -out server.crt

# Create client certificate
openssl genrsa -out client.key 4096
openssl req -new -key client.key -out client.csr
openssl x509 -req -days 365 -in client.csr -CA ca.crt -CAkey ca.key -set_serial 02 -out client.crt
```

## Troubleshooting

### Common Issues

**Edge Gateway not capturing packets**:
- Verify network interface name: `ip link show`
- Check permissions: Edge gateway needs NET_ADMIN and NET_RAW capabilities
- Verify promiscuous mode: `ip link set eth0 promisc on`

**AI Service not responding**:
- Check logs: `kubectl logs deployment/ai-service -n iot-ids`
- Verify Elasticsearch connectivity: `curl http://elasticsearch:9200`
- Check resource limits: `kubectl top pods -n iot-ids`

**Elasticsearch cluster unhealthy**:
- Check cluster health: `curl http://localhost:9200/_cluster/health`
- Verify storage: `kubectl get pvc -n iot-ids`
- Check logs: `kubectl logs statefulset/elasticsearch -n iot-ids`

**High memory usage**:
- Reduce batch sizes in configuration
- Enable compression and sampling
- Adjust JVM heap size for Elasticsearch

### Monitoring

**Check service metrics**:
```bash
# Prometheus metrics (if enabled)
curl http://localhost:9090/metrics

# Kubernetes metrics
kubectl top pods -n iot-ids
kubectl top nodes
```

**View logs**:
```bash
# Docker Compose
docker-compose logs -f [service-name]

# Kubernetes
kubectl logs -f deployment/ai-service -n iot-ids
kubectl logs -f daemonset/edge-gateway -n iot-ids
```

### Support

For additional help:
- Check documentation: `docs/`
- Review examples: `examples/`
- Open an issue: GitHub Issues
- Contact support: support@example.com
