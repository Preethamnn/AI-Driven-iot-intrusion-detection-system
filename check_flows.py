import requests
import json

try:
    r = requests.post('http://localhost:9200/iot-ids-network-flows/_search', 
                      json={'size':15, 'sort':[{'@timestamp':{'order':'desc'}}]}, timeout=5)
    data = r.json()
    hits = data.get('hits', {}).get('hits', [])
    print(f'Found {len(hits)} recent network flows:')
    for h in hits:
        s = h.get('_source', {})
        print(f"Time: {s.get('@timestamp')} | Src: {s.get('source_ip')}:{s.get('source_port')} -> Dst: {s.get('destination_ip')}:{s.get('destination_port')} [{s.get('protocol')}] | Pkts: {s.get('packets_sent')} | Bytes: {s.get('bytes_sent')}")
except Exception as e:
    print('Error:', e)
