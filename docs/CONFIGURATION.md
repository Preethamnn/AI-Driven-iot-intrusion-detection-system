# Configuration Guide

This guide explains all configuration options for the AI-Driven IoT IDS.

## Configuration Files

- `config/edge-gateway.yml`: Edge gateway configuration
- `config/ai-service.yml`: AI inference service configuration
- `k8s/configmaps.yaml`: Kubernetes configuration

## Edge Gateway Configuration

### Packet Capture

```yaml
edge_gateway:
  packet_capture:
    interface: "eth0"           # Network interface to monitor
    buffer_size_mb: 64          # Capture buffer size (1-1024 MB)
    capture_filter: ""          # BPF filter syntax
    promiscuous_mode: true      # Capture all packets on network
    snaplen: 65535              # Maximum bytes per packet
    use_ebpf: false             # Enable eBPF/XDP acceleration
    ring_buffer_size: 4096      # Ring buffer size
```

**BPF Filter Examples**:
```yaml
# Capture only TCP traffic
capture_filter: "tcp"

# Capture specific port
capture_filter: "port 443"

# Capture specific subnet
capture_filter: "net 192.168.1.0/24"

# Complex filter
capture_filter: "tcp and (port 80 or port 443) and not host 192.168.1.1"
```

### Protocol Decoders

```yaml
protocol_decoders:
  zeek_enabled: true
  zeek_scripts_path: "/opt/zeek/share/zeek/site"
  
  suricata_enabled: true
  suricata_config_path: "/etc/suricata/suricata.yaml"
  
  custom_rules_path: "/app/config/rules"
  
  # Protocol-specific extraction
  extract_dns: true
  extract_tls: true
  extract_http: true
  extract_mqtt: true
```

### Feature Extraction

```yaml
feature_extraction:
  flow_timeout_seconds: 300       # Flow idle timeout
  flow_max_duration_seconds: 3600 # Maximum flow duration
  
  # Feature types
  extract_timing_features: true
  extract_statistical_features: true
  extract_protocol_features: true
  extract_behavioral_features: true
  
  # Aggregation windows
  short_window_seconds: 60
  medium_window_seconds: 300
  long_window_seconds: 3600
```

### Device Profiling

```yaml
device_profiling:
  enabled: true
  oui_database_path: "/app/data/oui.txt"
  profile_learning_period_hours: 168  # 7 days
  profile_update_interval_hours: 24
  
  # Behavioral tracking
  track_periodicity: true
  track_bandwidth: true
  track_protocols: true
  track_destinations: true
```

### Data Forwarding

```yaml
forwarding:
  upstream_endpoints:
    - "http://ai-service:8000"
    - "http://backup-service:8000"  # Failover endpoint
  
  # Batching
  batch_size: 100
  flush_interval_ms: 1000
  max_queue_size: 10000
  
  # Retry logic
  retry_attempts: 3
  retry_backoff_ms: 1000
  retry_max_backoff_ms: 30000
  
  # Compression
  compression_enabled: true
  compression_algorithm: "gzip"  # Options: gzip, lz4, zstd
```

### Local Buffering

```yaml
local_buffering:
  enabled: true
  buffer_path: "/app/data/buffer"
  max_buffer_size_mb: 1024
  buffer_retention_hours: 24
  persist_to_disk: true
  sync_interval_seconds: 60
```

## AI Service Configuration

### Machine Learning Models

```yaml
ai_inference:
  models:
    # Isolation Forest (unsupervised)
    isolation_forest:
      enabled: true
      contamination: 0.1      # Expected outlier proportion (0.0-0.5)
      n_estimators: 100       # Number of trees
      max_samples: 256        # Samples per tree
      random_state: 42
    
    # XGBoost (supervised)
    xgboost:
      enabled: true
      max_depth: 6            # Tree depth (3-20)
      learning_rate: 0.1      # Step size (0.01-1.0)
      n_estimators: 100       # Boosting rounds
      objective: "binary:logistic"
      eval_metric: "auc"
      subsample: 0.8
      colsample_bytree: 0.8
    
    # CatBoost (supervised alternative)
    catboost:
      enabled: false
      iterations: 100
      learning_rate: 0.1
      depth: 6
      loss_function: "Logloss"
      eval_metric: "AUC"
    
    # Sequence models (temporal)
    sequence_models:
      enabled: false
      model_type: "gru"       # Options: gru, lstm, transformer
      hidden_size: 128
      num_layers: 2
      sequence_length: 10
      dropout: 0.2
```

### Feature Engineering

```yaml
feature_engineering:
  time_window_minutes: 5
  aggregation_functions:
    - mean
    - std
    - min
    - max
    - count
    - sum
  
  # Feature scaling
  scaling_method: "standard"  # Options: standard, minmax, robust
  
  # Feature selection
  feature_importance_threshold: 0.01
  max_features: 100
```

### Hybrid Decision Engine

```yaml
decision_engine:
  # Detection method weights
  signature_weight: 0.6       # Weight for signature-based (0-1)
  ml_weight: 0.4              # Weight for ML-based (0-1)
  
  # Severity thresholds
  threshold_low: 0.3
  threshold_medium: 0.5
  threshold_high: 0.7
  threshold_critical: 0.9
  
  # Score fusion method
  fusion_method: "weighted_average"  # Options: weighted_average, max, product
```

### API Configuration

```yaml
api:
  host: "0.0.0.0"
  rest_port: 8000
  grpc_port: 50051
  workers: 4                  # Number of worker processes
  max_batch_size: 100
  timeout_seconds: 30
  
  # CORS settings
  cors_enabled: true
  cors_origins:
    - "http://localhost:3000"
    - "https://dashboard.example.com"
```

## Storage Configuration

### Elasticsearch

```yaml
storage:
  elasticsearch:
    hosts:
      - "http://elasticsearch-0:9200"
      - "http://elasticsearch-1:9200"
      - "http://elasticsearch-2:9200"
    
    # Index settings
    index_prefix: "iot-ids"
    shard_count: 3
    replica_count: 1
    refresh_interval: "5s"
    
    # Connection settings
    timeout_seconds: 30
    max_retries: 3
    retry_on_timeout: true
    
    # Bulk indexing
    bulk_size: 500
    bulk_flush_interval_seconds: 10
    
    # Index Lifecycle Management
    ilm_policy:
      hot_phase_days: 7
      warm_phase_days: 30
      cold_phase_days: 90
      delete_phase_days: 365
```

### Data Retention

```yaml
retention:
  raw_data_days: 7            # Network flow data
  aggregated_data_days: 30    # Aggregated statistics
  alert_data_days: 90         # Threat alerts
  model_metrics_days: 180     # Model performance metrics
  audit_logs_days: 365        # Audit logs
```

## MLOps Configuration

### Model Registry

```yaml
mlops:
  model_registry:
    backend: "local"            # Options: local, mlflow, s3
    path: "/app/models"
    
    # MLflow settings (if backend=mlflow)
    mlflow_tracking_uri: "http://mlflow:5000"
    mlflow_experiment_name: "iot-ids"
    
    # S3 settings (if backend=s3)
    s3_bucket: "iot-ids-models"
    s3_prefix: "models/"
```

### Drift Monitoring

```yaml
drift_monitoring:
  enabled: true
  check_interval_hours: 24
  
  # Drift detection methods
  methods:
    - psi                       # Population Stability Index
    - ks                        # Kolmogorov-Smirnov
    - js                        # Jensen-Shannon divergence
  
  # Thresholds
  drift_threshold: 0.1
  performance_threshold: 0.8
  
  # Actions
  alert_on_drift: true
  auto_retrain: false
```

### Deployment

```yaml
deployment:
  strategy: "canary"            # Options: canary, blue_green, rolling
  canary_percentage: 10
  canary_duration_minutes: 60
  rollback_on_error: true
  
  # Health checks
  health_check_interval_seconds: 30
  health_check_timeout_seconds: 10
  health_check_failures_threshold: 3
```

## Security Configuration

### TLS/mTLS

```yaml
security:
  tls:
    enabled: true
    cert_path: "/app/certs/server.crt"
    key_path: "/app/certs/server.key"
    ca_path: "/app/certs/ca.crt"
    verify_client: true         # Enable mTLS
    
  # Certificate rotation
  certificate_rotation:
    enabled: true
    rotation_days: 30
    renewal_threshold_days: 7
```

### Authentication

```yaml
authentication:
  enabled: true
  api_key_header: "X-API-Key"
  
  # JWT settings (alternative)
  jwt_enabled: false
  jwt_secret: "your-secret-key"
  jwt_algorithm: "HS256"
  jwt_expiration_hours: 24
```

### Rate Limiting

```yaml
rate_limiting:
  enabled: true
  requests_per_minute: 1000
  burst_size: 100
  
  # Per-endpoint limits
  endpoints:
    "/api/v1/score":
      requests_per_minute: 5000
    "/api/v1/models/*/retrain":
      requests_per_minute: 10
```

### Network Security

```yaml
network_security:
  # VLAN configuration
  vlan_id: 100
  vlan_priority: 0
  
  # Firewall rules
  egress_policy: "deny_by_default"
  allowed_destinations:
    - "10.0.0.0/8"
    - "172.16.0.0/12"
    - "192.168.0.0/16"
  
  # Rate limiting
  rate_limit_enabled: true
  max_packets_per_second: 10000
```

## Observability Configuration

### Logging

```yaml
logging:
  level: "INFO"                 # DEBUG, INFO, WARNING, ERROR, CRITICAL
  format: "json"                # Options: json, text
  output: "stdout"              # Options: stdout, file, both
  file_path: "/app/logs/service.log"
  max_file_size_mb: 100
  backup_count: 5
  
  # Structured logging fields
  include_timestamp: true
  include_hostname: true
  include_process_id: true
```

### Metrics

```yaml
metrics:
  enabled: true
  prometheus_port: 9090
  collection_interval_seconds: 60
  
  # Custom metrics
  custom_metrics:
    - name: "flows_processed_total"
      type: "counter"
    - name: "inference_duration_seconds"
      type: "histogram"
```

### Alerting

```yaml
alerting:
  # Email alerts
  email:
    enabled: true
    smtp_host: "smtp.example.com"
    smtp_port: 587
    smtp_user: "alerts@example.com"
    smtp_password: "${SMTP_PASSWORD}"
    from_address: "alerts@example.com"
    to_addresses:
      - "security-team@example.com"
  
  # Slack alerts
  slack:
    enabled: true
    webhook_url: "${SLACK_WEBHOOK_URL}"
    channel: "#security-alerts"
    username: "IoT IDS"
  
  # Webhook alerts
  webhook:
    enabled: true
    url: "https://siem.example.com/api/alerts"
    headers:
      Authorization: "Bearer ${WEBHOOK_TOKEN}"
    timeout_seconds: 10
```

## Resource Management

### Memory Limits

```yaml
resources:
  max_memory_mb: 512
  flow_cache_size: 10000
  
  # Garbage collection
  gc_threshold_percent: 80
  gc_interval_seconds: 300
```

### CPU Limits

```yaml
resources:
  max_cpu_percent: 80
  worker_threads: 4
  
  # Thread pool settings
  thread_pool_size: 10
  thread_queue_size: 1000
```

### Disk Limits

```yaml
resources:
  max_disk_usage_percent: 80
  cleanup_threshold_percent: 90
  
  # Disk cleanup
  cleanup_enabled: true
  cleanup_interval_hours: 24
```

## Environment Variables

Configuration values can be overridden using environment variables:

```bash
# Edge Gateway
export EDGE_GATEWAY_INTERFACE=eth0
export EDGE_GATEWAY_BUFFER_SIZE_MB=128
export AI_SERVICE_URL=http://ai-service:8000

# AI Service
export AI_SERVICE_PORT=8000
export ELASTICSEARCH_HOST=http://elasticsearch:9200
export MODEL_PATH=/app/models

# Security
export TLS_CERT_PATH=/app/certs/server.crt
export TLS_KEY_PATH=/app/certs/server.key
export API_KEY=your-api-key-here

# Logging
export LOG_LEVEL=DEBUG
export LOG_FORMAT=json
```

## Configuration Validation

Validate configuration before deployment:

```bash
# Validate YAML syntax
python -m ai_iot_ids.utils.config_parser validate \
  --config config/ai-service.yml

# Test configuration
python -m ai_iot_ids.utils.config_parser test \
  --config config/ai-service.yml \
  --dry-run
```
