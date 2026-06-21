# API Documentation

The AI-Driven IoT IDS provides REST and gRPC APIs for threat detection and system management.

## Table of Contents

- [REST API](#rest-api)
- [gRPC API](#grpc-api)
- [Authentication](#authentication)
- [Rate Limiting](#rate-limiting)
- [Error Handling](#error-handling)

## REST API

Base URL: `http://ai-service:8000/api/v1`

### Health and Status

#### GET /health

Check service health status.

**Response**:
```json
{
  "status": "healthy",
  "timestamp": "2024-01-15T10:30:00Z",
  "models_loaded": true,
  "elasticsearch_connected": true,
  "version": "1.0.0"
}
```

#### GET /ready

Check if service is ready to accept requests.

**Response**:
```json
{
  "ready": true,
  "models": {
    "isolation_forest": "loaded",
    "xgboost": "loaded"
  }
}
```

### Threat Detection

#### POST /score

Score a network flow for threats.

**Request**:
```json
{
  "flow_id": "550e8400-e29b-41d4-a716-446655440000",
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
  "duration_ms": 5000,
  "features": {
    "inter_arrival_mean_ms": 500.0,
    "inter_arrival_std_ms": 100.0,
    "fan_out_ratio": 0.1,
    "port_distribution_entropy": 2.5
  }
}
```

**Response**:
```json
{
  "detection_id": "660e8400-e29b-41d4-a716-446655440001",
  "flow_id": "550e8400-e29b-41d4-a716-446655440000",
  "timestamp": "2024-01-15T10:30:01Z",
  "threat_score": 0.85,
  "confidence": 0.92,
  "severity": "high",
  "signature_matches": [
    {
      "rule_id": "ET-2024-001",
      "rule_name": "Suspicious DNS Query Pattern",
      "signature_score": 0.8
    }
  ],
  "ml_predictions": [
    {
      "model_name": "isolation_forest",
      "model_version": "1.0",
      "anomaly_score": 0.9,
      "feature_importance": {
        "fan_out_ratio": 0.35,
        "port_distribution_entropy": 0.25,
        "bytes_sent": 0.20
      }
    }
  ],
  "attack_category": "reconnaissance",
  "mitre_tactics": ["TA0043"],
  "recommended_actions": [
    "Monitor device for additional suspicious activity",
    "Review device allowlist configuration"
  ]
}
```

#### POST /score/batch

Score multiple network flows in a single request.

**Request**:
```json
{
  "flows": [
    {
      "flow_id": "550e8400-e29b-41d4-a716-446655440000",
      "source_ip": "192.168.1.100",
      ...
    },
    {
      "flow_id": "550e8400-e29b-41d4-a716-446655440001",
      "source_ip": "192.168.1.101",
      ...
    }
  ]
}
```

**Response**:
```json
{
  "results": [
    {
      "detection_id": "660e8400-e29b-41d4-a716-446655440001",
      "flow_id": "550e8400-e29b-41d4-a716-446655440000",
      "threat_score": 0.85,
      ...
    },
    {
      "detection_id": "660e8400-e29b-41d4-a716-446655440002",
      "flow_id": "550e8400-e29b-41d4-a716-446655440001",
      "threat_score": 0.15,
      ...
    }
  ],
  "processed": 2,
  "errors": 0
}
```

### Device Management

#### GET /devices

List all known devices.

**Query Parameters**:
- `limit` (optional): Maximum number of results (default: 100)
- `offset` (optional): Pagination offset (default: 0)
- `device_type` (optional): Filter by device type

**Response**:
```json
{
  "devices": [
    {
      "device_id": "aa:bb:cc:dd:ee:ff",
      "vendor_oui": "Nest Labs",
      "device_type": "thermostat",
      "firmware_version": "5.9.3",
      "first_seen": "2024-01-01T00:00:00Z",
      "last_seen": "2024-01-15T10:30:00Z",
      "threat_count": 0
    }
  ],
  "total": 1,
  "limit": 100,
  "offset": 0
}
```

#### GET /devices/{device_id}

Get detailed information about a specific device.

**Response**:
```json
{
  "device_id": "aa:bb:cc:dd:ee:ff",
  "vendor_oui": "Nest Labs",
  "device_type": "thermostat",
  "firmware_version": "5.9.3",
  "profile": {
    "normal_protocols": ["TCP", "UDP"],
    "allowed_destinations": ["192.168.1.1", "nest.com"],
    "typical_bandwidth_bps": 1024,
    "activity_schedule": {
      "hour_of_day": [0.1, 0.1, 0.1, ...],
      "day_of_week": [0.8, 0.8, 0.8, 0.8, 0.8, 0.3, 0.3]
    }
  },
  "statistics": {
    "total_flows": 10000,
    "total_bytes": 1048576,
    "threat_count": 0,
    "last_threat": null
  }
}
```

#### PUT /devices/{device_id}/profile

Update device profile.

**Request**:
```json
{
  "device_type": "thermostat",
  "allowed_destinations": ["192.168.1.1", "nest.com", "google.com"],
  "firmware_version": "5.9.4"
}
```

**Response**:
```json
{
  "device_id": "aa:bb:cc:dd:ee:ff",
  "updated": true,
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### Model Management

#### GET /models

List available ML models.

**Response**:
```json
{
  "models": [
    {
      "name": "isolation_forest",
      "version": "1.0",
      "status": "active",
      "accuracy": 0.95,
      "last_trained": "2024-01-01T00:00:00Z",
      "drift_score": 0.05
    },
    {
      "name": "xgboost",
      "version": "2.0",
      "status": "active",
      "accuracy": 0.93,
      "last_trained": "2024-01-10T00:00:00Z",
      "drift_score": 0.03
    }
  ]
}
```

#### GET /models/{model_name}/drift

Get drift metrics for a specific model.

**Response**:
```json
{
  "model_name": "isolation_forest",
  "version": "1.0",
  "drift_score": 0.05,
  "threshold": 0.1,
  "status": "healthy",
  "metrics": {
    "psi": 0.05,
    "ks_statistic": 0.03,
    "js_divergence": 0.02
  },
  "last_checked": "2024-01-15T10:00:00Z"
}
```

#### POST /models/{model_name}/retrain

Trigger model retraining.

**Request**:
```json
{
  "data_source": "elasticsearch",
  "start_date": "2024-01-01",
  "end_date": "2024-01-15",
  "validation_split": 0.2
}
```

**Response**:
```json
{
  "job_id": "retrain-550e8400-e29b-41d4-a716-446655440000",
  "status": "queued",
  "estimated_duration_minutes": 30
}
```

### Alerts

#### GET /alerts

Query threat alerts.

**Query Parameters**:
- `start_time` (optional): Start timestamp (ISO 8601)
- `end_time` (optional): End timestamp (ISO 8601)
- `severity` (optional): Filter by severity (low, medium, high, critical)
- `device_id` (optional): Filter by device ID
- `limit` (optional): Maximum results (default: 100)

**Response**:
```json
{
  "alerts": [
    {
      "detection_id": "660e8400-e29b-41d4-a716-446655440001",
      "timestamp": "2024-01-15T10:30:00Z",
      "device_id": "aa:bb:cc:dd:ee:ff",
      "threat_score": 0.85,
      "severity": "high",
      "attack_category": "reconnaissance",
      "status": "open"
    }
  ],
  "total": 1,
  "limit": 100
}
```

#### PUT /alerts/{detection_id}/status

Update alert status.

**Request**:
```json
{
  "status": "acknowledged",
  "notes": "Investigating suspicious activity"
}
```

**Response**:
```json
{
  "detection_id": "660e8400-e29b-41d4-a716-446655440001",
  "status": "acknowledged",
  "updated_by": "admin",
  "updated_at": "2024-01-15T10:35:00Z"
}
```

## gRPC API

The gRPC API provides high-performance inference for edge gateways.

### Service Definition

```protobuf
syntax = "proto3";

service ThreatDetection {
  rpc ScoreFlow(FlowRequest) returns (DetectionResponse);
  rpc ScoreFlowStream(stream FlowRequest) returns (stream DetectionResponse);
}

message FlowRequest {
  string flow_id = 1;
  string timestamp = 2;
  string source_ip = 3;
  string destination_ip = 4;
  int32 source_port = 5;
  int32 destination_port = 6;
  string protocol = 7;
  int64 bytes_sent = 8;
  int64 bytes_received = 9;
  int32 packets_sent = 10;
  int32 packets_received = 11;
  int64 duration_ms = 12;
  map<string, double> features = 13;
}

message DetectionResponse {
  string detection_id = 1;
  string flow_id = 2;
  string timestamp = 3;
  double threat_score = 4;
  double confidence = 5;
  string severity = 6;
  repeated SignatureMatch signature_matches = 7;
  repeated MLPrediction ml_predictions = 8;
}
```

### Usage Example (Python)

```python
import grpc
from ai_iot_ids.inference.api import threat_detection_pb2
from ai_iot_ids.inference.api import threat_detection_pb2_grpc

# Create channel
channel = grpc.insecure_channel('ai-service:50051')
stub = threat_detection_pb2_grpc.ThreatDetectionStub(channel)

# Create request
request = threat_detection_pb2.FlowRequest(
    flow_id="550e8400-e29b-41d4-a716-446655440000",
    source_ip="192.168.1.100",
    destination_ip="8.8.8.8",
    source_port=54321,
    destination_port=443,
    protocol="TCP",
    bytes_sent=1024,
    bytes_received=2048
)

# Call service
response = stub.ScoreFlow(request)
print(f"Threat score: {response.threat_score}")
```

## Authentication

All API requests require authentication using API keys.

**Header Format**:
```
X-API-Key: your-api-key-here
```

**Example**:
```bash
curl -H "X-API-Key: abc123xyz" http://ai-service:8000/api/v1/health
```

## Rate Limiting

API requests are rate-limited to prevent abuse:
- **Default**: 1000 requests per minute per API key
- **Burst**: Up to 100 requests in a 10-second window

**Rate Limit Headers**:
```
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 950
X-RateLimit-Reset: 1642248000
```

## Error Handling

### Error Response Format

```json
{
  "error": {
    "code": "INVALID_REQUEST",
    "message": "Missing required field: source_ip",
    "details": {
      "field": "source_ip",
      "expected_type": "string"
    }
  },
  "timestamp": "2024-01-15T10:30:00Z",
  "request_id": "req-550e8400-e29b-41d4-a716-446655440000"
}
```

### Error Codes

- `400 Bad Request`: Invalid request parameters
- `401 Unauthorized`: Missing or invalid API key
- `403 Forbidden`: Insufficient permissions
- `404 Not Found`: Resource not found
- `429 Too Many Requests`: Rate limit exceeded
- `500 Internal Server Error`: Server error
- `503 Service Unavailable`: Service temporarily unavailable

### HTTP Status Codes

| Code | Description |
|------|-------------|
| 200 | Success |
| 201 | Created |
| 400 | Bad Request |
| 401 | Unauthorized |
| 403 | Forbidden |
| 404 | Not Found |
| 429 | Too Many Requests |
| 500 | Internal Server Error |
| 503 | Service Unavailable |
