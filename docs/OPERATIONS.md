# Operations Guide

This guide covers day-to-day operations, monitoring, and maintenance of the AI-Driven IoT IDS.

## Table of Contents

- [System Monitoring](#system-monitoring)
- [Alert Management](#alert-management)
- [Model Management](#model-management)
- [Data Management](#data-management)
- [Backup and Recovery](#backup-and-recovery)
- [Performance Tuning](#performance-tuning)
- [Security Operations](#security-operations)

## System Monitoring

### Health Checks

**AI Service Health**:
```bash
# REST API health check
curl http://ai-service:8000/health

# Expected response:
# {"status": "healthy", "models_loaded": true, "elasticsearch_connected": true}
```

**Edge Gateway Health**:
```bash
# Check packet capture status
docker exec edge-gateway python -c "from ai_iot_ids.capture.scapy_capture import ScapyCapture; print('OK')"
```

**Elasticsearch Health**:
```bash
# Cluster health
curl http://elasticsearch:9200/_cluster/health?pretty

# Node stats
curl http://elasticsearch:9200/_nodes/stats?pretty
```

### Metrics Collection

**Prometheus Metrics** (if enabled):
- `iot_ids_packets_captured_total`: Total packets captured
- `iot_ids_flows_processed_total`: Total flows processed
- `iot_ids_threats_detected_total`: Total threats detected
- `iot_ids_model_inference_duration_seconds`: Model inference latency
- `iot_ids_queue_size`: Current queue size

**Kibana Dashboards**:

Access Kibana at `http://kibana:5601` and import dashboards:
1. Navigate to Management → Stack Management → Saved Objects
2. Import dashboard configurations from `config/kibana-dashboards/`

Key dashboards:
- **System Overview**: Overall system health and metrics
- **Threat Detection**: Real-time threat alerts and trends
- **Network Traffic**: Traffic patterns and anomalies
- **Model Performance**: ML model accuracy and drift metrics

### Log Analysis

**Centralized Logging**:

All logs are forwarded to Elasticsearch. Query logs using Kibana:

```
# View AI service logs
GET /iot-ids-logs-*/_search
{
  "query": {
    "match": {
      "service": "ai-service"
    }
  },
  "sort": [{"@timestamp": "desc"}]
}

# View error logs
GET /iot-ids-logs-*/_search
{
  "query": {
    "match": {
      "level": "ERROR"
    }
  }
}
```

**Log Levels**:
- DEBUG: Detailed diagnostic information
- INFO: General informational messages
- WARNING: Warning messages for potential issues
- ERROR: Error messages for failures
- CRITICAL: Critical failures requiring immediate attention

## Alert Management

### Alert Types

**Threat Alerts**:
- **Critical**: Confirmed malicious activity (score > 0.9)
- **High**: Likely malicious activity (score > 0.7)
- **Medium**: Suspicious activity (score > 0.5)
- **Low**: Anomalous activity (score > 0.3)

**System Alerts**:
- Model drift detected
- Service degradation
- Resource exhaustion
- Configuration errors

### Alert Channels

**Email Alerts**:
Configure in `config/ai-service.yml`:
```yaml
observability:
  alerting:
    email:
      enabled: true
      smtp_host: smtp.example.com
      smtp_port: 587
      from_address: alerts@example.com
      to_addresses:
        - security-team@example.com
```

**Slack Alerts**:
```yaml
observability:
  alerting:
    slack:
      enabled: true
      webhook_url: https://hooks.slack.com/services/YOUR/WEBHOOK/URL
      channel: "#security-alerts"
```

**Webhook Alerts**:
```yaml
observability:
  alerting:
    webhook:
      enabled: true
      url: https://your-siem.example.com/api/alerts
      headers:
        Authorization: "Bearer YOUR_TOKEN"
```

### Alert Response Procedures

**Critical Threat Alert**:
1. Verify alert in Kibana dashboard
2. Investigate source device and traffic patterns
3. Isolate affected device if confirmed malicious
4. Update device profile or allowlist if false positive
5. Document incident in ticketing system

**Model Drift Alert**:
1. Review model performance metrics
2. Analyze recent data distribution changes
3. Trigger model retraining if drift confirmed
4. Test new model in canary deployment
5. Promote to production if performance improves

## Model Management

### Model Deployment

**Deploy New Model**:
```bash
# Upload model to registry
python -m ai_iot_ids.mlops.model_registry upload \
  --model-path models/isolation_forest_v2.pkl \
  --model-name isolation_forest \
  --version 2.0 \
  --metadata '{"accuracy": 0.95, "training_date": "2024-01-15"}'

# Deploy with canary strategy
python -m ai_iot_ids.mlops.deployment_manager deploy \
  --model-name isolation_forest \
  --version 2.0 \
  --strategy canary \
  --canary-percentage 10
```

**Monitor Canary Deployment**:
```bash
# Check canary metrics
python -m ai_iot_ids.mlops.deployment_manager status \
  --model-name isolation_forest

# Promote to full deployment
python -m ai_iot_ids.mlops.deployment_manager promote \
  --model-name isolation_forest \
  --version 2.0

# Rollback if issues detected
python -m ai_iot_ids.mlops.deployment_manager rollback \
  --model-name isolation_forest
```

### Model Retraining

**Scheduled Retraining**:

Configure in `config/ai-service.yml`:
```yaml
mlops:
  retraining:
    enabled: true
    schedule: "0 2 * * 0"  # Weekly at 2 AM Sunday
    min_samples: 10000
    validation_split: 0.2
```

**Manual Retraining**:
```bash
# Trigger retraining
python -m ai_iot_ids.mlops.model_registry retrain \
  --model-name isolation_forest \
  --data-path /app/data/training_data.csv \
  --validation-split 0.2
```

### Drift Monitoring

**Check Drift Status**:
```bash
# View drift metrics
curl http://ai-service:8000/api/v1/drift/status

# Expected response:
# {
#   "isolation_forest": {
#     "drift_score": 0.05,
#     "threshold": 0.1,
#     "status": "healthy"
#   }
# }
```

**Drift Detection Methods**:
- Population Stability Index (PSI)
- Kolmogorov-Smirnov test
- Jensen-Shannon divergence
- Model performance degradation

## Data Management

### Index Management

**Elasticsearch Indices**:
- `iot-ids-flows-*`: Network flow data
- `iot-ids-threats-*`: Threat detection alerts
- `iot-ids-devices-*`: Device profiles
- `iot-ids-logs-*`: System logs

**Index Lifecycle Management**:

Indices automatically transition through phases:
1. **Hot** (0-7 days): Active indexing and querying
2. **Warm** (7-30 days): Read-only, optimized for queries
3. **Cold** (30-90 days): Compressed, infrequent access
4. **Delete** (>90 days): Automatically deleted

**Manual Index Operations**:
```bash
# List indices
curl http://elasticsearch:9200/_cat/indices?v

# Delete old indices
curl -X DELETE http://elasticsearch:9200/iot-ids-flows-2024.01.*

# Reindex data
curl -X POST http://elasticsearch:9200/_reindex -H 'Content-Type: application/json' -d'
{
  "source": {"index": "iot-ids-flows-old"},
  "dest": {"index": "iot-ids-flows-new"}
}'
```

### Data Retention

**Configure Retention Policies**:
```yaml
storage:
  retention:
    raw_data_days: 7
    aggregated_data_days: 30
    alert_data_days: 90
    model_metrics_days: 180
```

**Manual Cleanup**:
```bash
# Clean up old data
python -m ai_iot_ids.utils.data_cleanup \
  --older-than 90 \
  --index-pattern "iot-ids-flows-*" \
  --dry-run

# Execute cleanup
python -m ai_iot_ids.utils.data_cleanup \
  --older-than 90 \
  --index-pattern "iot-ids-flows-*"
```

## Backup and Recovery

### Elasticsearch Snapshots

**Configure Snapshot Repository**:
```bash
# Create repository
curl -X PUT http://elasticsearch:9200/_snapshot/backup_repo -H 'Content-Type: application/json' -d'
{
  "type": "fs",
  "settings": {
    "location": "/mnt/backups/elasticsearch"
  }
}'
```

**Create Snapshot**:
```bash
# Manual snapshot
curl -X PUT http://elasticsearch:9200/_snapshot/backup_repo/snapshot_$(date +%Y%m%d) -H 'Content-Type: application/json' -d'
{
  "indices": "iot-ids-*",
  "ignore_unavailable": true,
  "include_global_state": false
}'

# Check snapshot status
curl http://elasticsearch:9200/_snapshot/backup_repo/_all
```

**Restore from Snapshot**:
```bash
# Close indices
curl -X POST http://elasticsearch:9200/iot-ids-*/_close

# Restore snapshot
curl -X POST http://elasticsearch:9200/_snapshot/backup_repo/snapshot_20240115/_restore

# Open indices
curl -X POST http://elasticsearch:9200/iot-ids-*/_open
```

### Model Backup

**Backup Models**:
```bash
# Backup model registry
tar -czf models-backup-$(date +%Y%m%d).tar.gz /app/models/

# Upload to S3 (if configured)
aws s3 cp models-backup-$(date +%Y%m%d).tar.gz s3://your-bucket/backups/
```

**Restore Models**:
```bash
# Download from S3
aws s3 cp s3://your-bucket/backups/models-backup-20240115.tar.gz .

# Extract
tar -xzf models-backup-20240115.tar.gz -C /app/models/

# Restart AI service
kubectl rollout restart deployment/ai-service -n iot-ids
```

## Performance Tuning

### Edge Gateway Optimization

**Packet Capture Performance**:
```yaml
edge_gateway:
  packet_capture:
    use_ebpf: true              # Enable eBPF for better performance
    ring_buffer_size: 8192      # Increase buffer size
    worker_threads: 4           # Match CPU cores
```

**Memory Optimization**:
```yaml
resources:
  max_memory_mb: 512
  flow_cache_size: 10000        # Reduce if memory constrained
```

### AI Service Optimization

**Batch Processing**:
```yaml
ai_inference:
  api:
    max_batch_size: 100         # Increase for higher throughput
    workers: 8                  # Scale with CPU cores
```

**Model Optimization**:
- Use quantized models for faster inference
- Enable GPU acceleration if available
- Cache frequently used features

### Elasticsearch Optimization

**JVM Heap Size**:
```yaml
environment:
  ES_JAVA_OPTS: "-Xms4g -Xmx4g"  # Set to 50% of available RAM
```

**Shard Configuration**:
```yaml
storage:
  elasticsearch:
    shard_count: 3              # 1 shard per 50GB of data
    replica_count: 1            # At least 1 replica for HA
```

## Security Operations

### Certificate Rotation

**Automatic Rotation** (recommended):
```yaml
security:
  certificate_rotation:
    enabled: true
    rotation_days: 30
    renewal_threshold_days: 7
```

**Manual Rotation**:
```bash
# Generate new certificates
./scripts/generate-certs.sh

# Update Kubernetes secrets
kubectl create secret tls iot-ids-tls \
  --cert=certs/server.crt \
  --key=certs/server.key \
  --namespace=iot-ids \
  --dry-run=client -o yaml | kubectl apply -f -

# Restart services
kubectl rollout restart deployment/ai-service -n iot-ids
```

### Access Control

**API Key Management**:
```bash
# Generate new API key
python -m ai_iot_ids.security.api_keys generate \
  --name "edge-gateway-01" \
  --permissions "read,write"

# Revoke API key
python -m ai_iot_ids.security.api_keys revoke \
  --key-id "abc123"

# List active keys
python -m ai_iot_ids.security.api_keys list
```

### Audit Logging

**Enable Audit Logs**:
```yaml
security:
  audit_logging:
    enabled: true
    log_path: /app/logs/audit.log
    events:
      - authentication
      - authorization
      - configuration_change
      - model_deployment
```

**Query Audit Logs**:
```bash
# View recent authentication events
grep "authentication" /app/logs/audit.log | tail -n 100

# Search in Elasticsearch
curl http://elasticsearch:9200/iot-ids-audit-*/_search -H 'Content-Type: application/json' -d'
{
  "query": {
    "match": {
      "event_type": "authentication"
    }
  }
}'
```

### Incident Response

**Isolate Compromised Device**:
```bash
# Add device to blocklist
python -m ai_iot_ids.profiling.device_profile_manager block \
  --device-id "aa:bb:cc:dd:ee:ff" \
  --reason "Confirmed malicious activity"

# Update firewall rules
python -m ai_iot_ids.security.network_security update-rules \
  --action deny \
  --source "aa:bb:cc:dd:ee:ff"
```

**Forensic Data Collection**:
```bash
# Export device traffic history
python -m ai_iot_ids.utils.forensics export \
  --device-id "aa:bb:cc:dd:ee:ff" \
  --start-time "2024-01-15T00:00:00Z" \
  --end-time "2024-01-15T23:59:59Z" \
  --output device-forensics.json
```
