"""
Property-based test for configuration round-trip consistency.

This module implements Property 10: Configuration Round-Trip Consistency
using Hypothesis to verify that parsing -> serializing -> parsing
produces equivalent configuration objects.

**Feature: ai-driven-iot-ids, Property 10: Configuration Round-Trip Consistency**
**Validates: Requirements 10.1, 10.4, 10.5**
"""

import pytest
from hypothesis import given, strategies as st, settings, assume
from typing import Dict, Any, List

from ai_iot_ids.models.system_configuration import (
    SystemConfiguration, EdgeGatewayConfig, PacketCaptureConfig,
    ProtocolDecodersConfig, ForwardingConfig, AIInferenceConfig,
    StorageConfig, ElasticsearchConfig, RetentionConfig,
    ModelsConfig, IsolationForestConfig, XGBoostConfig,
    FeatureEngineeringConfig, DecisionEngineConfig, AggregationFunction
)
from ai_iot_ids.utils.config_parser import YAMLConfigParser
from ai_iot_ids.utils.error_handling import ConfigurationError


# Hypothesis strategies for generating valid configuration data

@st.composite
def valid_interface_name(draw):
    """Generate valid network interface names."""
    prefixes = ["eth", "wlan", "lo", "docker", "br"]
    prefix = draw(st.sampled_from(prefixes))
    suffix = draw(st.integers(min_value=0, max_value=99))
    return f"{prefix}{suffix}"


@st.composite
def valid_url_list(draw):
    """Generate valid URL lists."""
    protocols = ["http", "https"]
    hosts = ["localhost", "elasticsearch", "ai-service", "logstash"]
    ports = [8080, 9200, 5000, 8000]
    
    count = draw(st.integers(min_value=1, max_value=3))
    urls = []
    for _ in range(count):
        protocol = draw(st.sampled_from(protocols))
        host = draw(st.sampled_from(hosts))
        port = draw(st.sampled_from(ports))
        urls.append(f"{protocol}://{host}:{port}")
    return urls


@st.composite
def valid_bpf_filter(draw):
    """Generate valid BPF filter expressions."""
    filters = [
        "",
        "not port 22",
        "tcp and port 80",
        "udp and port 53",
        "icmp",
        "host 192.168.1.1",
        "net 192.168.0.0/16"
    ]
    return draw(st.sampled_from(filters))


@st.composite
def valid_file_path(draw):
    """Generate valid file paths."""
    paths = [
        "/etc/ids/rules",
        "/var/lib/ids/config",
        "/opt/ids/data",
        "/tmp/ids",
        "/usr/local/ids"
    ]
    return draw(st.sampled_from(paths))


@st.composite
def packet_capture_config_strategy(draw):
    """Generate PacketCaptureConfig instances."""
    return PacketCaptureConfig(
        interface=draw(valid_interface_name()),
        buffer_size_mb=draw(st.integers(min_value=1, max_value=1024)),
        capture_filter=draw(valid_bpf_filter())
    )


@st.composite
def protocol_decoders_config_strategy(draw):
    """Generate ProtocolDecodersConfig instances."""
    return ProtocolDecodersConfig(
        zeek_enabled=draw(st.booleans()),
        suricata_enabled=draw(st.booleans()),
        custom_rules_path=draw(valid_file_path())
    )


@st.composite
def forwarding_config_strategy(draw):
    """Generate ForwardingConfig instances."""
    return ForwardingConfig(
        upstream_endpoints=draw(valid_url_list()),
        batch_size=draw(st.integers(min_value=1, max_value=10000)),
        flush_interval_ms=draw(st.integers(min_value=100, max_value=60000)),
        retry_attempts=draw(st.integers(min_value=1, max_value=10))
    )


@st.composite
def edge_gateway_config_strategy(draw):
    """Generate EdgeGatewayConfig instances."""
    return EdgeGatewayConfig(
        packet_capture=draw(packet_capture_config_strategy()),
        protocol_decoders=draw(protocol_decoders_config_strategy()),
        forwarding=draw(forwarding_config_strategy())
    )


@st.composite
def isolation_forest_config_strategy(draw):
    """Generate IsolationForestConfig instances."""
    return IsolationForestConfig(
        enabled=draw(st.booleans()),
        contamination=draw(st.floats(min_value=0.0, max_value=0.5)),
        n_estimators=draw(st.integers(min_value=50, max_value=1000))
    )


@st.composite
def xgboost_config_strategy(draw):
    """Generate XGBoostConfig instances."""
    return XGBoostConfig(
        enabled=draw(st.booleans()),
        max_depth=draw(st.integers(min_value=3, max_value=20)),
        learning_rate=draw(st.floats(min_value=0.01, max_value=1.0)),
        n_estimators=draw(st.integers(min_value=50, max_value=1000))
    )


@st.composite
def models_config_strategy(draw):
    """Generate ModelsConfig instances."""
    return ModelsConfig(
        isolation_forest=draw(isolation_forest_config_strategy()),
        xgboost=draw(xgboost_config_strategy())
    )


@st.composite
def feature_engineering_config_strategy(draw):
    """Generate FeatureEngineeringConfig instances."""
    # Ensure at least one aggregation function is selected
    all_functions = list(AggregationFunction)
    selected_count = draw(st.integers(min_value=1, max_value=len(all_functions)))
    selected_functions = draw(st.lists(
        st.sampled_from(all_functions),
        min_size=selected_count,
        max_size=selected_count,
        unique=True
    ))
    
    return FeatureEngineeringConfig(
        time_window_minutes=draw(st.integers(min_value=1, max_value=60)),
        aggregation_functions=selected_functions
    )


@st.composite
def decision_engine_config_strategy(draw):
    """Generate DecisionEngineConfig instances."""
    # Generate weights that sum to 1.0
    signature_weight = draw(st.floats(min_value=0.0, max_value=1.0))
    ml_weight = 1.0 - signature_weight
    
    # Generate ordered thresholds
    threshold_low = draw(st.floats(min_value=0.0, max_value=0.8))
    threshold_high = draw(st.floats(min_value=threshold_low + 0.1, max_value=1.0))
    
    return DecisionEngineConfig(
        signature_weight=signature_weight,
        ml_weight=ml_weight,
        threshold_low=threshold_low,
        threshold_high=threshold_high
    )


@st.composite
def ai_inference_config_strategy(draw):
    """Generate AIInferenceConfig instances."""
    return AIInferenceConfig(
        models=draw(models_config_strategy()),
        feature_engineering=draw(feature_engineering_config_strategy()),
        decision_engine=draw(decision_engine_config_strategy())
    )


@st.composite
def elasticsearch_config_strategy(draw):
    """Generate ElasticsearchConfig instances."""
    return ElasticsearchConfig(
        hosts=draw(valid_url_list()),
        index_prefix=draw(st.text(min_size=1, max_size=20, alphabet=st.characters(
            whitelist_categories=('Ll', 'Lu', 'Nd'), whitelist_characters='-_'
        ))),
        shard_count=draw(st.integers(min_value=1, max_value=10)),
        replica_count=draw(st.integers(min_value=0, max_value=5))
    )


@st.composite
def retention_config_strategy(draw):
    """Generate RetentionConfig instances."""
    return RetentionConfig(
        raw_data_days=draw(st.integers(min_value=1, max_value=365)),
        aggregated_data_days=draw(st.integers(min_value=1, max_value=1095)),
        alert_data_days=draw(st.integers(min_value=1, max_value=2555))
    )


@st.composite
def storage_config_strategy(draw):
    """Generate StorageConfig instances."""
    return StorageConfig(
        elasticsearch=draw(elasticsearch_config_strategy()),
        retention=draw(retention_config_strategy())
    )


@st.composite
def system_configuration_strategy(draw):
    """Generate SystemConfiguration instances."""
    edge_gateway = draw(edge_gateway_config_strategy())
    ai_inference = draw(ai_inference_config_strategy())
    storage = draw(storage_config_strategy())
    
    # Ensure at least one model is enabled for validation
    if not (ai_inference.models.isolation_forest.enabled or 
            ai_inference.models.xgboost.enabled):
        ai_inference.models.isolation_forest.enabled = True
    
    return SystemConfiguration(
        edge_gateway=edge_gateway,
        ai_inference=ai_inference,
        storage=storage
    )


class TestConfigurationRoundTripConsistency:
    """
    Property-based tests for configuration round-trip consistency.
    
    **Feature: ai-driven-iot-ids, Property 10: Configuration Round-Trip Consistency**
    **Validates: Requirements 10.1, 10.4, 10.5**
    """
    
    @given(config=system_configuration_strategy())
    @settings(max_examples=100, deadline=5000)
    def test_configuration_round_trip_consistency(self, config: SystemConfiguration):
        """
        Test that parsing -> serializing -> parsing produces equivalent configuration.
        
        **Property 10: Configuration Round-Trip Consistency**
        For any valid SystemConfiguration object, parsing the configuration from YAML,
        then serializing it back to YAML, then parsing again should produce an
        equivalent configuration object with all detection rules and parameters preserved.
        
        **Validates: Requirements 10.1, 10.4, 10.5**
        """
        parser = YAMLConfigParser()
        
        # Step 1: Serialize the original configuration to YAML
        yaml_content = parser.serialize(config)
        
        # Verify YAML content is not empty
        assert yaml_content.strip(), "Serialized YAML should not be empty"
        
        # Step 2: Parse the YAML back to a configuration object
        parsed_config = parser.parse(yaml_content, SystemConfiguration)
        
        # Step 3: Serialize the parsed configuration again
        yaml_content_2 = parser.serialize(parsed_config)
        
        # Step 4: Parse the second YAML to ensure consistency
        parsed_config_2 = parser.parse(yaml_content_2, SystemConfiguration)
        
        # Verify round-trip consistency
        original_dict = config.model_dump()
        parsed_dict = parsed_config.model_dump()
        parsed_dict_2 = parsed_config_2.model_dump()
        
        # All three should be equivalent
        assert original_dict == parsed_dict, "First round-trip should preserve all data"
        assert parsed_dict == parsed_dict_2, "Second round-trip should be identical"
        assert original_dict == parsed_dict_2, "Multiple round-trips should be consistent"
        
        # Verify YAML content is also consistent
        assert yaml_content == yaml_content_2, "YAML serialization should be deterministic"
    
    @given(config=system_configuration_strategy())
    @settings(max_examples=50, deadline=3000)
    def test_configuration_validation_preserved(self, config: SystemConfiguration):
        """
        Test that configuration validation is preserved through round-trip.
        
        **Property 10: Configuration Round-Trip Consistency (Validation Aspect)**
        Configuration validation should pass both before and after round-trip processing.
        
        **Validates: Requirements 10.2, 10.4**
        """
        parser = YAMLConfigParser()
        
        # Original configuration should be valid
        assert config.validate_configuration() is True
        
        # Round-trip the configuration
        yaml_content = parser.serialize(config)
        parsed_config = parser.parse(yaml_content, SystemConfiguration)
        
        # Parsed configuration should also be valid
        assert parsed_config.validate_configuration() is True
        
        # Specific validation checks should be preserved
        assert config.get_enabled_models() == parsed_config.get_enabled_models()
        assert config.get_total_retention_days() == parsed_config.get_total_retention_days()
        assert config.is_high_performance_mode() == parsed_config.is_high_performance_mode()
    
    @given(config=system_configuration_strategy())
    @settings(max_examples=30, deadline=2000)
    def test_yaml_syntax_validity(self, config: SystemConfiguration):
        """
        Test that serialized YAML has valid syntax.
        
        **Property 10: Configuration Round-Trip Consistency (Syntax Aspect)**
        Serialized configuration should always produce valid YAML syntax.
        
        **Validates: Requirements 10.1, 10.2**
        """
        parser = YAMLConfigParser()
        
        # Serialize configuration
        yaml_content = parser.serialize(config)
        
        # Verify YAML syntax is valid
        assert parser.validate_syntax(yaml_content) is True
        
        # Verify content contains expected sections
        assert "edge_gateway" in yaml_content
        assert "ai_inference" in yaml_content
        assert "storage" in yaml_content
        
        # Verify YAML is properly formatted (basic checks)
        lines = yaml_content.split('\n')
        assert len(lines) > 10, "YAML should have reasonable structure"
        
        # Check for proper indentation (no tabs, consistent spaces)
        for line in lines:
            if line.strip():  # Skip empty lines
                assert '\t' not in line, "YAML should not contain tabs"
    
    def test_round_trip_with_sample_configuration(self, sample_system_configuration):
        """
        Test round-trip consistency with a known good configuration.
        
        This is a concrete example test to complement the property-based tests.
        """
        parser = YAMLConfigParser()
        
        # Perform round-trip
        yaml_content = parser.serialize(sample_system_configuration)
        parsed_config = parser.parse(yaml_content, SystemConfiguration)
        
        # Verify specific fields are preserved
        assert (sample_system_configuration.edge_gateway.packet_capture.interface == 
                parsed_config.edge_gateway.packet_capture.interface)
        assert (sample_system_configuration.storage.elasticsearch.hosts == 
                parsed_config.storage.elasticsearch.hosts)
        assert (sample_system_configuration.ai_inference.models.isolation_forest.enabled == 
                parsed_config.ai_inference.models.isolation_forest.enabled)
    
    def test_round_trip_error_handling(self):
        """
        Test error handling during round-trip operations.
        
        Verifies that invalid configurations are properly rejected.
        """
        parser = YAMLConfigParser()
        
        # Test with invalid YAML syntax
        invalid_yaml = "invalid: yaml: content: ["
        with pytest.raises(ConfigurationError) as exc_info:
            parser.parse(invalid_yaml, SystemConfiguration)
        assert "YAML syntax error" in str(exc_info.value)
        
        # Test with structurally invalid configuration
        invalid_config_yaml = """
        edge_gateway:
          packet_capture:
            buffer_size_mb: -1  # Invalid negative value
        storage:
          elasticsearch:
            hosts: []  # Invalid empty list
        """
        with pytest.raises(ConfigurationError):
            parser.parse(invalid_config_yaml, SystemConfiguration)