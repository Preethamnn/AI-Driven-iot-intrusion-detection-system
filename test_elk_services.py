#!/usr/bin/env python3
"""
Test script for Elasticsearch and Kibana services
"""

import requests
import json
import time
import sys

def test_elasticsearch():
    """Test Elasticsearch service"""
    try:
        print("🔍 Testing Elasticsearch...")
        response = requests.get("http://localhost:9200/_cluster/health", timeout=10)
        
        if response.status_code == 200:
            health = response.json()
            print(f"✅ Elasticsearch is healthy")
            print(f"   Status: {health.get('status', 'unknown')}")
            print(f"   Cluster: {health.get('cluster_name', 'unknown')}")
            print(f"   Nodes: {health.get('number_of_nodes', 0)}")
            return True
        else:
            print(f"❌ Elasticsearch returned status {response.status_code}")
            return False
            
    except requests.exceptions.RequestException as e:
        print(f"❌ Elasticsearch is not accessible: {e}")
        return False

def test_kibana():
    """Test Kibana service"""
    try:
        print("\n📊 Testing Kibana...")
        response = requests.get("http://localhost:5601/api/status", timeout=10)
        
        if response.status_code == 200:
            print("✅ Kibana is accessible")
            print("   Dashboard URL: http://localhost:5601")
            return True
        else:
            print(f"❌ Kibana returned status {response.status_code}")
            return False
            
    except requests.exceptions.RequestException as e:
        print(f"❌ Kibana is not accessible: {e}")
        return False

def create_sample_data():
    """Create sample IoT network data in Elasticsearch"""
    try:
        print("\n📝 Creating sample IoT network data...")
        
        # Sample IoT network flow data
        sample_data = [
            {
                "timestamp": "2026-02-27T15:00:00Z",
                "src_ip": "192.168.1.100",
                "dst_ip": "8.8.8.8",
                "src_port": 12345,
                "dst_port": 53,
                "protocol": "UDP",
                "bytes": 64,
                "packets": 1,
                "device_type": "IoT_Sensor",
                "threat_level": "low",
                "anomaly_score": 0.1
            },
            {
                "timestamp": "2026-02-27T15:01:00Z",
                "src_ip": "192.168.1.101",
                "dst_ip": "malicious.example.com",
                "src_port": 54321,
                "dst_port": 80,
                "protocol": "TCP",
                "bytes": 1024,
                "packets": 10,
                "device_type": "IoT_Camera",
                "threat_level": "high",
                "anomaly_score": 0.9
            },
            {
                "timestamp": "2026-02-27T15:02:00Z",
                "src_ip": "192.168.1.102",
                "dst_ip": "api.weather.com",
                "src_port": 443,
                "dst_port": 443,
                "protocol": "TCP",
                "bytes": 512,
                "packets": 5,
                "device_type": "IoT_Thermostat",
                "threat_level": "low",
                "anomaly_score": 0.2
            }
        ]
        
        # Index sample data
        for i, data in enumerate(sample_data):
            response = requests.post(
                f"http://localhost:9200/iot-ids-demo/_doc/{i+1}",
                json=data,
                headers={"Content-Type": "application/json"},
                timeout=10
            )
            
            if response.status_code in [200, 201]:
                print(f"   ✅ Indexed sample record {i+1}")
            else:
                print(f"   ❌ Failed to index record {i+1}: {response.status_code}")
        
        # Refresh index
        requests.post("http://localhost:9200/iot-ids-demo/_refresh", timeout=10)
        print("   📊 Sample data indexed successfully")
        return True
        
    except Exception as e:
        print(f"❌ Error creating sample data: {e}")
        return False

def main():
    """Main test function"""
    print("🚀 Testing ELK Stack for IoT IDS")
    print("=" * 50)
    
    # Test services
    es_ok = test_elasticsearch()
    kibana_ok = test_kibana()
    
    if es_ok and kibana_ok:
        print("\n🎉 Both services are running successfully!")
        
        # Create sample data
        if create_sample_data():
            print("\n📋 Next Steps:")
            print("1. Open Kibana: http://localhost:5601")
            print("2. Go to 'Discover' to explore the sample data")
            print("3. Create visualizations for IoT network monitoring")
            print("4. Set up dashboards for threat detection")
            
            print("\n🔍 Sample Data Created:")
            print("   Index: iot-ids-demo")
            print("   Records: 3 sample IoT network flows")
            print("   Fields: timestamp, IPs, ports, device_type, threat_level, anomaly_score")
            
        return True
    else:
        print("\n❌ Some services are not working properly")
        print("Please check Docker containers and try again")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)