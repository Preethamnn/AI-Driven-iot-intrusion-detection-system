"""
Logstash pipeline integration for data transformation and enrichment.

This module provides integration with Logstash for data processing,
structured logging, and event enrichment.
"""

import json
import logging
import logging.config
from datetime import datetime
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, asdict
from pathlib import Path

from ..models.network_flow import NetworkFlow
from ..models.threat_detection import ThreatDetection
from ..models.device_profile import DeviceProfile
from ..utils.error_handling import IDSError


@dataclass
class LogstashConfig:
    """Configuration for Logstash pipeline integration."""
    pipeline_name: str
    input_type: str = "beats"
    output_elasticsearch_hosts: List[str] = None
    filter_rules: List[str] = None
    
    def __post_init__(self):
        if self.output_elasticsearch_hosts is None:
            self.output_elasticsearch_hosts = ["localhost:9200"]
        if self.filter_rules is None:
            self.filter_rules = []


class StructuredLogger:
    """
    Structured JSON logger for IDS events.
    
    Provides consistent JSON formatting for all log events
    with proper field mapping and enrichment.
    """
    
    def __init__(self, logger_name: str = "ai_iot_ids", log_level: str = "INFO"):
        """
        Initialize structured logger.
        
        Args:
            logger_name: Name of the logger
            log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        """
        self.logger_name = logger_name
        self.logger = logging.getLogger(logger_name)
        
        # Configure JSON formatter
        self._configure_json_logging(log_level)
    
    def _configure_json_logging(self, log_level: str):
        """Configure JSON logging format."""
        
        class JSONFormatter(logging.Formatter):
            """Custom JSON formatter for structured logging."""
            
            def format(self, record):
                log_entry = {
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "level": record.levelname,
                    "logger": record.name,
                    "message": record.getMessage(),
                    "module": record.module,
                    "function": record.funcName,
                    "line": record.lineno
                }
                
                # Add exception information if present
                if record.exc_info:
                    log_entry["exception"] = self.formatException(record.exc_info)
                
                # Add extra fields from record
                for key, value in record.__dict__.items():
                    if key not in ['name', 'msg', 'args', 'levelname', 'levelno', 
                                 'pathname', 'filename', 'module', 'lineno', 
                                 'funcName', 'created', 'msecs', 'relativeCreated',
                                 'thread', 'threadName', 'processName', 'process',
                                 'getMessage', 'exc_info', 'exc_text', 'stack_info']:
                        log_entry[key] = value
                
                return json.dumps(log_entry, default=str)
        
        # Remove existing handlers (if handlers attribute exists and is iterable)
        if hasattr(self.logger, 'handlers') and hasattr(self.logger.handlers, '__iter__'):
            for handler in list(self.logger.handlers):
                self.logger.removeHandler(handler)
        
        # Create console handler with JSON formatter
        handler = logging.StreamHandler()
        handler.setFormatter(JSONFormatter())
        
        # Set log level
        level = getattr(logging, log_level.upper(), logging.INFO)
        self.logger.setLevel(level)
        handler.setLevel(level)
        
        self.logger.addHandler(handler)
        self.logger.propagate = False
    
    def log_network_flow(self, flow: NetworkFlow, extra_fields: Optional[Dict[str, Any]] = None):
        """
        Log network flow event with structured format.
        
        Args:
            flow: Network flow data
            extra_fields: Additional fields to include
        """
        log_data = {
            "event_type": "network_flow",
            "flow_id": flow.flow_id,
            "source_ip": flow.source_ip,
            "destination_ip": flow.destination_ip,
            "source_port": flow.source_port,
            "destination_port": flow.destination_port,
            "protocol": flow.protocol,
            "bytes_total": flow.bytes_sent + flow.bytes_received,
            "packets_total": flow.packets_sent + flow.packets_received,
            "duration_ms": flow.duration_ms
        }
        
        if extra_fields:
            log_data.update(extra_fields)
        
        self.logger.info("Network flow processed", extra=log_data)
    
    def log_threat_detection(self, detection: ThreatDetection, extra_fields: Optional[Dict[str, Any]] = None):
        """
        Log threat detection event with structured format.
        
        Args:
            detection: Threat detection data
            extra_fields: Additional fields to include
        """
        log_data = {
            "event_type": "threat_detection",
            "detection_id": detection.detection_id,
            "device_id": detection.device_id,
            "threat_score": detection.threat_score,
            "confidence": detection.confidence,
            "severity": detection.severity.value,
            "attack_category": detection.attack_category.value if detection.attack_category else None,
            "signature_matches_count": len(detection.signature_matches),
            "ml_predictions_count": len(detection.ml_predictions)
        }
        
        if extra_fields:
            log_data.update(extra_fields)
        
        self.logger.warning("Threat detected", extra=log_data)
    
    def log_device_profile_update(self, profile: DeviceProfile, extra_fields: Optional[Dict[str, Any]] = None):
        """
        Log device profile update event with structured format.
        
        Args:
            profile: Device profile data
            extra_fields: Additional fields to include
        """
        log_data = {
            "event_type": "device_profile_update",
            "device_id": profile.device_id,
            "vendor_oui": profile.vendor_oui,
            "device_type": profile.device_type.value,
            "confidence_score": profile.confidence_score,
            "observation_count": profile.observation_count
        }
        
        if extra_fields:
            log_data.update(extra_fields)
        
        self.logger.info("Device profile updated", extra=log_data)
    
    def log_system_event(self, event_type: str, message: str, level: str = "INFO", **kwargs):
        """
        Log generic system event with structured format.
        
        Args:
            event_type: Type of system event
            message: Event message
            level: Log level
            **kwargs: Additional fields
        """
        log_data = {
            "event_type": event_type,
            **kwargs
        }
        
        log_level = getattr(logging, level.upper(), logging.INFO)
        self.logger.log(log_level, message, extra=log_data)


class LogstashPipeline:
    """
    Logstash pipeline integration for data transformation and enrichment.
    
    Provides functionality for:
    - Data transformation and enrichment
    - Pipeline configuration generation
    - Event validation and error handling
    - Integration with Elasticsearch output
    """
    
    def __init__(self, config: LogstashConfig):
        """
        Initialize Logstash pipeline integration.
        
        Args:
            config: Logstash configuration
        """
        self.config = config
        self.logger = StructuredLogger(f"logstash_pipeline_{config.pipeline_name}")
        self._validation_errors = []
    
    def generate_pipeline_config(self) -> str:
        """
        Generate Logstash pipeline configuration.
        
        Returns:
            Logstash pipeline configuration as string
        """
        config = f"""
# Logstash pipeline configuration for {self.config.pipeline_name}
input {{
  beats {{
    port => 5044
  }}
  
  http {{
    port => 8080
    codec => json
  }}
}}

filter {{
  # Parse timestamp
  date {{
    match => [ "timestamp", "ISO8601" ]
    target => "@timestamp"
  }}
  
  # Add pipeline metadata
  mutate {{
    add_field => {{
      "pipeline_name" => "{self.config.pipeline_name}"
      "processed_at" => "%{{+YYYY-MM-dd'T'HH:mm:ss.SSSZ}}"
    }}
  }}
  
  # Process network flow events
  if [event_type] == "network_flow" {{
    # Calculate derived fields
    ruby {{
      code => '
        bytes_sent = event.get("bytes_sent") || 0
        bytes_received = event.get("bytes_received") || 0
        event.set("bytes_total", bytes_sent + bytes_received)
        
        packets_sent = event.get("packets_sent") || 0
        packets_received = event.get("packets_received") || 0
        event.set("packets_total", packets_sent + packets_received)
        
        duration_ms = event.get("duration_ms") || 1
        if duration_ms > 0
          event.set("bytes_per_second", (bytes_sent + bytes_received) * 1000.0 / duration_ms)
          event.set("packets_per_second", (packets_sent + packets_received) * 1000.0 / duration_ms)
        end
      '
    }}
    
    # Enrich with GeoIP data
    geoip {{
      source => "source_ip"
      target => "source_geo"
    }}
    
    geoip {{
      source => "destination_ip"
      target => "destination_geo"
    }}
  }}
  
  # Process threat detection events
  if [event_type] == "threat_detection" {{
    # Parse MITRE ATT&CK tactics
    if [mitre_tactics] {{
      mutate {{
        split => {{ "mitre_tactics" => "," }}
      }}
    }}
    
    # Set alert priority based on severity
    if [severity] == "critical" {{
      mutate {{ add_field => {{ "alert_priority" => 1 }} }}
    }} else if [severity] == "high" {{
      mutate {{ add_field => {{ "alert_priority" => 2 }} }}
    }} else if [severity] == "medium" {{
      mutate {{ add_field => {{ "alert_priority" => 3 }} }}
    }} else {{
      mutate {{ add_field => {{ "alert_priority" => 4 }} }}
    }}
  }}
  
  # Process device profile events
  if [event_type] == "device_profile_update" {{
    # Parse activity schedule if present
    if [activity_schedule] {{
      json {{
        source => "activity_schedule"
        target => "activity_schedule_parsed"
      }}
    }}
  }}
  
  # Add custom filter rules
{self._generate_custom_filters()}
  
  # Validate required fields
  if ![timestamp] or ![event_type] {{
    mutate {{
      add_tag => [ "validation_error", "missing_required_fields" ]
    }}
  }}
  
  # Remove sensitive fields
  mutate {{
    remove_field => [ "host", "agent", "ecs", "input" ]
  }}
}}

output {{
  # Send to Elasticsearch
  elasticsearch {{
    hosts => {json.dumps(self.config.output_elasticsearch_hosts)}
    index => "%{{event_type}}-%{{+YYYY.MM.dd}}"
    template_name => "ids_template"
    template_pattern => "*"
    template_overwrite => true
    template => {{
      "index_patterns": ["*"],
      "settings": {{
        "number_of_shards": 1,
        "number_of_replicas": 0
      }},
      "mappings": {{
        "properties": {{
          "timestamp": {{ "type": "date" }},
          "event_type": {{ "type": "keyword" }},
          "threat_score": {{ "type": "float" }},
          "confidence": {{ "type": "float" }},
          "severity": {{ "type": "keyword" }}
        }}
      }}
    }}
  }}
  
  # Send validation errors to dead letter queue
  if "validation_error" in [tags] {{
    elasticsearch {{
      hosts => {json.dumps(self.config.output_elasticsearch_hosts)}
      index => "validation-errors-%{{+YYYY.MM.dd}}"
    }}
  }}
  
  # Debug output (remove in production)
  if [event_type] == "threat_detection" and [severity] in ["high", "critical"] {{
    stdout {{
      codec => json_lines
    }}
  }}
}}
"""
        return config.strip()
    
    def _generate_custom_filters(self) -> str:
        """Generate custom filter rules from configuration."""
        if not self.config.filter_rules:
            return "  # No custom filter rules configured"
        
        filters = []
        for rule in self.config.filter_rules:
            filters.append(f"  {rule}")
        
        return "\n".join(filters)
    
    def validate_event(self, event: Dict[str, Any]) -> bool:
        """
        Validate event data before processing.
        
        Args:
            event: Event data to validate
            
        Returns:
            True if event is valid
        """
        self._validation_errors.clear()
        
        # Check required fields
        required_fields = ["timestamp", "event_type"]
        for field in required_fields:
            if field not in event:
                self._validation_errors.append(f"Missing required field: {field}")
        
        # Validate timestamp format
        if "timestamp" in event:
            try:
                datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
            except (ValueError, AttributeError):
                self._validation_errors.append("Invalid timestamp format")
        
        # Validate event type
        valid_event_types = ["network_flow", "threat_detection", "device_profile_update", "system_event"]
        if event.get("event_type") not in valid_event_types:
            self._validation_errors.append(f"Invalid event_type: {event.get('event_type')}")
        
        # Event-specific validation
        if event.get("event_type") == "threat_detection":
            self._validate_threat_detection_event(event)
        elif event.get("event_type") == "network_flow":
            self._validate_network_flow_event(event)
        
        return len(self._validation_errors) == 0
    
    def _validate_threat_detection_event(self, event: Dict[str, Any]):
        """Validate threat detection specific fields."""
        if "threat_score" in event:
            try:
                score = float(event["threat_score"])
                if not (0.0 <= score <= 1.0):
                    self._validation_errors.append("threat_score must be between 0.0 and 1.0")
            except (ValueError, TypeError):
                self._validation_errors.append("threat_score must be a valid float")
        
        if "severity" in event:
            valid_severities = ["low", "medium", "high", "critical"]
            if event["severity"] not in valid_severities:
                self._validation_errors.append(f"Invalid severity: {event['severity']}")
    
    def _validate_network_flow_event(self, event: Dict[str, Any]):
        """Validate network flow specific fields."""
        numeric_fields = ["source_port", "destination_port", "bytes_sent", "bytes_received", 
                         "packets_sent", "packets_received", "duration_ms"]
        
        for field in numeric_fields:
            if field in event:
                try:
                    value = int(event[field])
                    if value < 0:
                        self._validation_errors.append(f"{field} must be non-negative")
                except (ValueError, TypeError):
                    self._validation_errors.append(f"{field} must be a valid integer")
    
    def get_validation_errors(self) -> List[str]:
        """Get list of validation errors from last validation."""
        return self._validation_errors.copy()
    
    def enrich_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enrich event with additional metadata and computed fields.
        
        Args:
            event: Original event data
            
        Returns:
            Enriched event data
        """
        enriched = event.copy()
        
        # Add processing metadata
        enriched["processed_at"] = datetime.utcnow().isoformat() + "Z"
        enriched["pipeline_name"] = self.config.pipeline_name
        
        # Add computed fields based on event type
        if event.get("event_type") == "network_flow":
            self._enrich_network_flow(enriched)
        elif event.get("event_type") == "threat_detection":
            self._enrich_threat_detection(enriched)
        
        return enriched
    
    def _enrich_network_flow(self, event: Dict[str, Any]):
        """Enrich network flow event with computed fields."""
        # Calculate total bytes and packets
        bytes_sent = event.get("bytes_sent", 0)
        bytes_received = event.get("bytes_received", 0)
        event["bytes_total"] = bytes_sent + bytes_received
        
        packets_sent = event.get("packets_sent", 0)
        packets_received = event.get("packets_received", 0)
        event["packets_total"] = packets_sent + packets_received
        
        # Calculate rates
        duration_ms = event.get("duration_ms", 1)
        if duration_ms > 0:
            event["bytes_per_second"] = (bytes_sent + bytes_received) * 1000.0 / duration_ms
            event["packets_per_second"] = (packets_sent + packets_received) * 1000.0 / duration_ms
        
        # Classify flow direction
        src_port = event.get("source_port", 0)
        dst_port = event.get("destination_port", 0)
        
        # Common service ports
        well_known_ports = {80: "http", 443: "https", 53: "dns", 22: "ssh", 
                           21: "ftp", 25: "smtp", 110: "pop3", 143: "imap"}
        
        if dst_port in well_known_ports:
            event["service"] = well_known_ports[dst_port]
            event["flow_direction"] = "outbound"
        elif src_port in well_known_ports:
            event["service"] = well_known_ports[src_port]
            event["flow_direction"] = "inbound"
        else:
            event["flow_direction"] = "unknown"
    
    def _enrich_threat_detection(self, event: Dict[str, Any]):
        """Enrich threat detection event with computed fields."""
        # Set alert priority based on severity
        severity = event.get("severity", "low")
        priority_map = {"critical": 1, "high": 2, "medium": 3, "low": 4}
        event["alert_priority"] = priority_map.get(severity, 4)
        
        # Calculate combined score from signature and ML predictions
        signature_scores = []
        ml_scores = []
        
        for match in event.get("signature_matches", []):
            if "signature_score" in match:
                signature_scores.append(match["signature_score"])
        
        for prediction in event.get("ml_predictions", []):
            if "anomaly_score" in prediction:
                ml_scores.append(prediction["anomaly_score"])
        
        if signature_scores:
            event["max_signature_score"] = max(signature_scores)
            event["avg_signature_score"] = sum(signature_scores) / len(signature_scores)
        
        if ml_scores:
            event["max_ml_score"] = max(ml_scores)
            event["avg_ml_score"] = sum(ml_scores) / len(ml_scores)
    
    def process_batch(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Process a batch of events with validation and enrichment.
        
        Args:
            events: List of events to process
            
        Returns:
            Processing results with counts and errors
        """
        results = {
            "total_events": len(events),
            "valid_events": 0,
            "invalid_events": 0,
            "enriched_events": [],
            "validation_errors": []
        }
        
        for i, event in enumerate(events):
            try:
                if self.validate_event(event):
                    enriched = self.enrich_event(event)
                    results["enriched_events"].append(enriched)
                    results["valid_events"] += 1
                else:
                    results["invalid_events"] += 1
                    results["validation_errors"].append({
                        "event_index": i,
                        "errors": self.get_validation_errors()
                    })
                    
            except Exception as e:
                results["invalid_events"] += 1
                results["validation_errors"].append({
                    "event_index": i,
                    "errors": [f"Processing error: {str(e)}"]
                })
        
        self.logger.log_system_event(
            "batch_processing_complete",
            f"Processed {results['total_events']} events",
            total_events=results["total_events"],
            valid_events=results["valid_events"],
            invalid_events=results["invalid_events"]
        )
        
        return results
    
    def save_pipeline_config(self, output_path: str) -> bool:
        """
        Save generated pipeline configuration to file.
        
        Args:
            output_path: Path to save configuration file
            
        Returns:
            True if configuration was saved successfully
        """
        try:
            config_content = self.generate_pipeline_config()
            
            output_file = Path(output_path)
            output_file.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_file, 'w') as f:
                f.write(config_content)
            
            self.logger.log_system_event(
                "pipeline_config_saved",
                f"Pipeline configuration saved to {output_path}",
                config_path=output_path,
                pipeline_name=self.config.pipeline_name
            )
            
            return True
            
        except Exception as e:
            self.logger.log_system_event(
                "pipeline_config_save_error",
                f"Failed to save pipeline configuration: {e}",
                level="ERROR",
                config_path=output_path,
                error=str(e)
            )
            return False