"""
Ingest train_test_network.csv into Elasticsearch for Kibana visualization.
Run this after ELK stack is up: python ingest_to_elasticsearch.py
"""
import csv
import json
import urllib.request
import urllib.error
from datetime import datetime, timedelta
import random
import sys

ES_URL = "http://localhost:9200"
INDEX_NAME = "iot-network-flows"

NUMERIC_FIELDS = [
    "src_port", "dst_port", "duration", "src_bytes", "dst_bytes",
    "missed_bytes", "src_pkts", "src_ip_bytes", "dst_pkts", "dst_ip_bytes",
    "dns_qclass", "dns_qtype", "dns_rcode", "http_trans_depth",
    "http_request_body_len", "http_response_body_len", "http_status_code", "label"
]

BOOL_FIELDS = ["dns_AA", "dns_RD", "dns_RA", "dns_rejected", "ssl_resumed", "ssl_established", "weird_notice"]


def check_elasticsearch():
    try:
        req = urllib.request.urlopen(f"{ES_URL}/_cluster/health", timeout=5)
        health = json.loads(req.read())
        print(f"Elasticsearch status: {health['status']}")
        return True
    except Exception as e:
        print(f"Cannot reach Elasticsearch at {ES_URL}: {e}")
        print("Make sure your ELK containers are running first.")
        return False


def create_index():
    mapping = {
        "mappings": {
            "properties": {
                "@timestamp": {"type": "date"},
                "src_ip": {"type": "ip"},
                "dst_ip": {"type": "ip"},
                "src_port": {"type": "integer"},
                "dst_port": {"type": "integer"},
                "proto": {"type": "keyword"},
                "service": {"type": "keyword"},
                "duration": {"type": "float"},
                "src_bytes": {"type": "long"},
                "dst_bytes": {"type": "long"},
                "conn_state": {"type": "keyword"},
                "label": {"type": "integer"},
                "type": {"type": "keyword"},
                "threat_label": {"type": "keyword"}
            }
        }
    }
    # Delete existing index
    try:
        req = urllib.request.Request(f"{ES_URL}/{INDEX_NAME}", method="DELETE")
        urllib.request.urlopen(req, timeout=5)
        print(f"Deleted existing index '{INDEX_NAME}'")
    except Exception:
        pass

    # Create new index
    data = json.dumps(mapping).encode("utf-8")
    req = urllib.request.Request(
        f"{ES_URL}/{INDEX_NAME}",
        data=data,
        method="PUT",
        headers={"Content-Type": "application/json"}
    )
    urllib.request.urlopen(req, timeout=5)
    print(f"Created index '{INDEX_NAME}'")


def parse_row(row, timestamp):
    doc = {"@timestamp": timestamp.isoformat()}

    for key, value in row.items():
        if value in ("-", "", None):
            continue
        if key in NUMERIC_FIELDS:
            try:
                doc[key] = float(value) if "." in value else int(value)
            except ValueError:
                doc[key] = value
        elif key in BOOL_FIELDS:
            doc[key] = value.upper() in ("T", "TRUE", "1")
        else:
            doc[key] = value

    # Add human-readable threat label
    label = doc.get("label", 0)
    attack_type = doc.get("type", "normal")
    if label == 1:
        doc["threat_label"] = attack_type
        doc["is_threat"] = True
    else:
        doc["threat_label"] = "normal"
        doc["is_threat"] = False

    return doc


def bulk_ingest(docs):
    lines = []
    for doc in docs:
        lines.append(json.dumps({"index": {"_index": INDEX_NAME}}))
        lines.append(json.dumps(doc))
    body = "\n".join(lines) + "\n"

    req = urllib.request.Request(
        f"{ES_URL}/_bulk",
        data=body.encode("utf-8"),
        method="POST",
        headers={"Content-Type": "application/x-ndjson"}
    )
    resp = urllib.request.urlopen(req, timeout=30)
    result = json.loads(resp.read())
    if result.get("errors"):
        # Count actual errors
        errors = [i for i in result["items"] if i.get("index", {}).get("error")]
        return len(docs) - len(errors), len(errors)
    return len(docs), 0


def main():
    print("IoT IDS — Elasticsearch Data Ingestion")
    print("=" * 40)

    if not check_elasticsearch():
        sys.exit(1)

    create_index()

    # Spread timestamps over the last 24 hours so Kibana shows a timeline
    base_time = datetime.utcnow()
    total_rows = 0
    with open("train_test_network.csv", "r") as f:
        total_rows = sum(1 for _ in f) - 1  # subtract header
    print(f"Total records to ingest: {total_rows:,}")

    batch = []
    batch_size = 500
    ingested = 0
    errors = 0
    time_step = timedelta(hours=24) / max(total_rows, 1)

    with open("train_test_network.csv", "r") as f:
        reader = csv.DictReader(f)
        for i, row in enumerate(reader):
            # Spread records across last 24h with slight jitter
            ts = base_time - timedelta(hours=24) + (time_step * i)
            ts += timedelta(seconds=random.uniform(-30, 30))
            doc = parse_row(row, ts)
            batch.append(doc)

            if len(batch) >= batch_size:
                ok, err = bulk_ingest(batch)
                ingested += ok
                errors += err
                batch = []
                print(f"  Ingested {ingested:,} / {total_rows:,} records...", end="\r")

    if batch:
        ok, err = bulk_ingest(batch)
        ingested += ok
        errors += err

    print(f"\nDone. Ingested: {ingested:,} | Errors: {errors}")
    print(f"\nNext steps:")
    print(f"  1. Open Kibana: http://localhost:5601")
    print(f"  2. Go to: Stack Management → Index Patterns → Create index pattern")
    print(f"  3. Pattern: iot-network-flows*  |  Time field: @timestamp")
    print(f"  4. Go to Discover or Dashboard to explore the data")


if __name__ == "__main__":
    main()
