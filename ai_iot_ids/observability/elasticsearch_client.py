"""
Elasticsearch client for data management and lifecycle policies.

This module provides Elasticsearch integration with index template creation,
ILM policy management, and data retention policies.
"""

import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass

try:
    from elasticsearch import Elasticsearch
    from elasticsearch.exceptions import ConnectionError, RequestError, NotFoundError
except ImportError:
    # Graceful degradation if elasticsearch-py is not installed
    Elasticsearch = None
    ConnectionError = Exception
    RequestError = Exception
    NotFoundError = Exception

from ..models.network_flow import NetworkFlow
from ..models.threat_detection import ThreatDetection
from ..models.device_profile import DeviceProfile
from ..utils.error_handling import IDSError


@dataclass
class IndexConfig:
    """Configuration for Elasticsearch index."""
    name: str
    shards: int = 1
    replicas: int = 0
    refresh_interval: str = "30s"
    max_result_window: int = 10000


@dataclass
class ILMPolicy:
    """Index Lifecycle Management policy configuration."""
    name: str
    hot_phase_max_size: str = "50gb"
    hot_phase_max_age: str = "30d"
    warm_phase_max_age: str = "90d"
    cold_phase_max_age: str = "365d"
    delete_phase_max_age: str = "2555d"  # 7 years


class ElasticsearchClient:
    """
    Elasticsearch client for AI-driven IoT IDS data management.
    
    Provides functionality for:
    - Index template creation and management
    - ILM policy configuration
    - Data ingestion and querying
    - Retention policy enforcement
    """
    
    def __init__(
        self,
        hosts: List[str],
        username: Optional[str] = None,
        password: Optional[str] = None,
        ca_certs: Optional[str] = None,
        verify_certs: bool = True,
        timeout: int = 30
    ):
        """
        Initialize Elasticsearch client.
        
        Args:
            hosts: List of Elasticsearch host URLs
            username: Authentication username
            password: Authentication password
            ca_certs: Path to CA certificate file
            verify_certs: Whether to verify SSL certificates
            timeout: Request timeout in seconds
        """
        if Elasticsearch is None:
            raise IDSError("elasticsearch-py package is required but not installed")
            
        self.logger = logging.getLogger(__name__)
        
        # Configure authentication
        auth = None
        if username and password:
            auth = (username, password)
            
        # Configure SSL
        ssl_context = {}
        if ca_certs:
            ssl_context['ca_certs'] = ca_certs
        ssl_context['verify_certs'] = verify_certs
        
        try:
            self.client = Elasticsearch(
                hosts=hosts,
                http_auth=auth,
                request_timeout=timeout,
                retry_on_timeout=True,
                max_retries=3
            )
            
            # Test connection
            try:
                if not self.client.ping():
                    self.logger.warning("Failed to ping Elasticsearch cluster, but continuing anyway.")
            except Exception as e:
                self.logger.warning(f"Ping failed: {e}. Continuing anyway.")
                
            self.logger.info(f"Connected to Elasticsearch cluster: {hosts}")
            
        except Exception as e:
            raise IDSError(f"Failed to initialize Elasticsearch client: {e}")
    
    def create_index_template(self, template_name: str, index_pattern: str, mappings: Dict[str, Any]) -> bool:
        """
        Create or update an index template.
        
        Args:
            template_name: Name of the template
            index_pattern: Index pattern to match (e.g., "network-flows-*")
            mappings: Field mappings for the template
            
        Returns:
            True if template was created/updated successfully
        """
        try:
            template_body = {
                "index_patterns": [index_pattern],
                "template": {
                    "settings": {
                        "number_of_shards": 1,
                        "number_of_replicas": 0,
                        "refresh_interval": "30s",
                        "index.lifecycle.name": f"{template_name}-policy",
                        "index.lifecycle.rollover_alias": template_name
                    },
                    "mappings": mappings
                },
                "priority": 100,
                "version": 1
            }
            
            response = self.client.indices.put_index_template(
                name=template_name,
                body=template_body
            )
            
            self.logger.info(f"Created index template: {template_name}")
            return response.get('acknowledged', False)
            
        except RequestError as e:
            self.logger.error(f"Failed to create index template {template_name}: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Unexpected error creating index template {template_name}: {e}")
            return False
    
    def create_ilm_policy(self, policy: ILMPolicy) -> bool:
        """
        Create or update an ILM policy.
        
        Args:
            policy: ILM policy configuration
            
        Returns:
            True if policy was created/updated successfully
        """
        try:
            policy_body = {
                "policy": {
                    "phases": {
                        "hot": {
                            "actions": {
                                "rollover": {
                                    "max_size": policy.hot_phase_max_size,
                                    "max_age": policy.hot_phase_max_age
                                }
                            }
                        },
                        "warm": {
                            "min_age": policy.warm_phase_max_age,
                            "actions": {
                                "allocate": {
                                    "number_of_replicas": 0
                                }
                            }
                        },
                        "cold": {
                            "min_age": policy.cold_phase_max_age,
                            "actions": {
                                "allocate": {
                                    "number_of_replicas": 0
                                }
                            }
                        },
                        "delete": {
                            "min_age": policy.delete_phase_max_age
                        }
                    }
                }
            }
            
            response = self.client.ilm.put_lifecycle(
                name=policy.name,
                body=policy_body
            )
            
            self.logger.info(f"Created ILM policy: {policy.name}")
            return response.get('acknowledged', False)
            
        except RequestError as e:
            self.logger.error(f"Failed to create ILM policy {policy.name}: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Unexpected error creating ILM policy {policy.name}: {e}")
            return False
    
    def setup_network_flow_index(self) -> bool:
        """
        Set up index template and ILM policy for network flow data.
        
        Returns:
            True if setup was successful
        """
        # Define mappings for network flow data
        mappings = {
            "properties": {
                "flow_id": {"type": "keyword"},
                "timestamp": {"type": "date"},
                "source_ip": {"type": "ip"},
                "destination_ip": {"type": "ip"},
                "source_port": {"type": "integer"},
                "destination_port": {"type": "integer"},
                "protocol": {"type": "keyword"},
                "bytes_sent": {"type": "long"},
                "bytes_received": {"type": "long"},
                "packets_sent": {"type": "long"},
                "packets_received": {"type": "long"},
                "duration_ms": {"type": "long"},
                "inter_arrival_mean_ms": {"type": "float"},
                "inter_arrival_std_ms": {"type": "float"},
                "jitter_ms": {"type": "float"},
                "tcp_flags": {"type": "keyword"},
                "retransmissions": {"type": "integer"},
                "syn_fin_ratio": {"type": "float"},
                "unique_destinations": {"type": "integer"},
                "fan_out_ratio": {"type": "float"},
                "fan_in_ratio": {"type": "float"},
                "port_distribution_entropy": {"type": "float"}
            }
        }
        
        # Create ILM policy for network flows (shorter retention)
        flow_policy = ILMPolicy(
            name="network-flows-policy",
            hot_phase_max_size="10gb",
            hot_phase_max_age="7d",
            warm_phase_max_age="30d",
            cold_phase_max_age="90d",
            delete_phase_max_age="365d"  # 1 year retention
        )
        
        policy_success = self.create_ilm_policy(flow_policy)
        template_success = self.create_index_template(
            "network-flows",
            "network-flows-*",
            mappings
        )
        
        return policy_success and template_success
    
    def setup_threat_detection_index(self) -> bool:
        """
        Set up index template and ILM policy for threat detection data.
        
        Returns:
            True if setup was successful
        """
        # Define mappings for threat detection data
        mappings = {
            "properties": {
                "detection_id": {"type": "keyword"},
                "timestamp": {"type": "date"},
                "source_flow_id": {"type": "keyword"},
                "device_id": {"type": "keyword"},
                "threat_score": {"type": "float"},
                "confidence": {"type": "float"},
                "severity": {"type": "keyword"},
                "signature_matches": {
                    "type": "nested",
                    "properties": {
                        "rule_id": {"type": "keyword"},
                        "rule_name": {"type": "text"},
                        "signature_score": {"type": "float"}
                    }
                },
                "ml_predictions": {
                    "type": "nested",
                    "properties": {
                        "model_name": {"type": "keyword"},
                        "model_version": {"type": "keyword"},
                        "anomaly_score": {"type": "float"},
                        "feature_importance": {"type": "object"}
                    }
                },
                "attack_category": {"type": "keyword"},
                "mitre_tactics": {"type": "keyword"},
                "recommended_actions": {"type": "text"}
            }
        }
        
        # Create ILM policy for threat detections (longer retention)
        threat_policy = ILMPolicy(
            name="threat-detections-policy",
            hot_phase_max_size="5gb",
            hot_phase_max_age="30d",
            warm_phase_max_age="90d",
            cold_phase_max_age="365d",
            delete_phase_max_age="2555d"  # 7 years retention
        )
        
        policy_success = self.create_ilm_policy(threat_policy)
        template_success = self.create_index_template(
            "threat-detections",
            "threat-detections-*",
            mappings
        )
        
        return policy_success and template_success
    
    def setup_device_profile_index(self) -> bool:
        """
        Set up index template and ILM policy for device profile data.
        
        Returns:
            True if setup was successful
        """
        # Define mappings for device profile data
        mappings = {
            "properties": {
                "device_id": {"type": "keyword"},
                "vendor_oui": {"type": "keyword"},
                "device_type": {"type": "keyword"},
                "firmware_version": {"type": "keyword"},
                "normal_protocols": {"type": "keyword"},
                "allowed_destinations": {"type": "keyword"},
                "typical_bandwidth_bps": {"type": "long"},
                "activity_schedule": {
                    "properties": {
                        "hour_of_day": {"type": "float"},
                        "day_of_week": {"type": "float"}
                    }
                },
                "profile_created": {"type": "date"},
                "last_updated": {"type": "date"},
                "confidence_score": {"type": "float"},
                "observation_count": {"type": "long"}
            }
        }
        
        # Create ILM policy for device profiles (long retention)
        profile_policy = ILMPolicy(
            name="device-profiles-policy",
            hot_phase_max_size="1gb",
            hot_phase_max_age="90d",
            warm_phase_max_age="365d",
            cold_phase_max_age="1095d",
            delete_phase_max_age="2555d"  # 7 years retention
        )
        
        policy_success = self.create_ilm_policy(profile_policy)
        template_success = self.create_index_template(
            "device-profiles",
            "device-profiles-*",
            mappings
        )
        
        return policy_success and template_success
    
    def initialize_indices(self) -> bool:
        """
        Initialize all required indices with templates and ILM policies.
        
        Returns:
            True if all indices were initialized successfully
        """
        try:
            flow_success = self.setup_network_flow_index()
            threat_success = self.setup_threat_detection_index()
            profile_success = self.setup_device_profile_index()
            
            success = flow_success and threat_success and profile_success
            
            if success:
                self.logger.info("All Elasticsearch indices initialized successfully")
            else:
                self.logger.warning("Some Elasticsearch indices failed to initialize")
                
            return success
            
        except Exception as e:
            self.logger.error(f"Failed to initialize Elasticsearch indices: {e}")
            return False
    
    def index_document(self, index: str, document: Dict[str, Any], doc_id: Optional[str] = None) -> bool:
        """
        Index a document in Elasticsearch.
        
        Args:
            index: Index name
            document: Document to index
            doc_id: Optional document ID
            
        Returns:
            True if document was indexed successfully
        """
        try:
            response = self.client.index(
                index=index,
                body=document,
                id=doc_id,
                refresh='wait_for'
            )
            
            return response.get('result') in ['created', 'updated']
            
        except Exception as e:
            self.logger.error(f"Failed to index document in {index}: {e}")
            return False
    
    def bulk_index_documents(self, index: str, documents: List[Dict[str, Any]]) -> int:
        """
        Bulk index multiple documents.
        
        Args:
            index: Index name
            documents: List of documents to index
            
        Returns:
            Number of successfully indexed documents
        """
        if not documents:
            return 0
            
        try:
            from elasticsearch.helpers import bulk
            
            actions = []
            for doc in documents:
                action = {
                    "_index": index,
                    "_source": doc
                }
                actions.append(action)
            
            success_count, failed_items = bulk(
                self.client,
                actions,
                refresh='wait_for',
                request_timeout=60
            )
            
            if failed_items:
                self.logger.warning(f"Failed to index {len(failed_items)} documents")
                
            return success_count
            
        except Exception as e:
            self.logger.error(f"Failed to bulk index documents: {e}")
            return 0
    
    def search_documents(
        self,
        index: str,
        query: Dict[str, Any],
        size: int = 100,
        sort: Optional[List[Dict[str, Any]]] = None
    ) -> List[Dict[str, Any]]:
        """
        Search for documents in an index.
        
        Args:
            index: Index name or pattern
            query: Elasticsearch query DSL
            size: Maximum number of results
            sort: Sort criteria
            
        Returns:
            List of matching documents
        """
        try:
            search_body = {
                "query": query,
                "size": size
            }
            
            if sort:
                search_body["sort"] = sort
                
            response = self.client.search(
                index=index,
                body=search_body
            )
            
            hits = response.get('hits', {}).get('hits', [])
            return [hit['_source'] for hit in hits]
            
        except Exception as e:
            self.logger.error(f"Failed to search documents in {index}: {e}")
            return []
    
    def get_cluster_health(self) -> Dict[str, Any]:
        """
        Get cluster health information.
        
        Returns:
            Cluster health status
        """
        try:
            return self.client.cluster.health()
        except Exception as e:
            self.logger.error(f"Failed to get cluster health: {e}")
            return {"status": "unknown", "error": str(e)}
    
    def close(self):
        """Close the Elasticsearch client connection."""
        try:
            if hasattr(self.client, 'close'):
                self.client.close()
        except Exception as e:
            self.logger.error(f"Error closing Elasticsearch client: {e}")