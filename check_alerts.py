import requests
import json
import time

try:
    r = requests.post('http://localhost:9200/iot-ids-alerts/_search', 
                      json={'size':20, 'sort':[{'@timestamp':{'order':'desc'}}]}, timeout=5)
    data = r.json()
    hits = data.get('hits', {}).get('hits', [])
    print(f'Found {len(hits)} recent alerts:')
    for h in hits:
        s = h.get('_source', {})
        print(f"Time: {s.get('@timestamp')} | Src: {s.get('source_ip')}:{s.get('source_port')} -> Dst: {s.get('destination_ip')}:{s.get('destination_port')} [{s.get('protocol')}] | Score: {s.get('threat_score')} | Severity: {s.get('severity')} | Category: {s.get('attack_category')}")
except Exception as e:
    print('Error:', e)
