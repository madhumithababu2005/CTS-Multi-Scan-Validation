import os
import json
import argparse
import sys

def parse_args():
    parser = argparse.ArgumentParser(description="Ingest ZAP SARIF report and output normalized findings.")
    parser.add_argument(
        "--input", 
        default="scans/scan_01/zap_report.sarif.json",
        help="Path to the input ZAP SARIF file"
    )
    parser.add_argument(
        "--output", 
        default="scans/scan_01/normalized_findings.json",
        help="Path to the output normalized findings file"
    )
    return parser.parse_args()

def extract_http_details(result):
    # Extracts HTTP method, headers, and body if present in SARIF properties
    method = "GET"
    request_headers = {}
    request_body = ""
    
    # Try to find ZAP custom properties
    properties = result.get("properties", {})
    
    # ZAP often places request/response info in properties
    for key, value in properties.items():
        if "request" in key.lower() or "http" in key.lower():
            if isinstance(value, dict):
                method = value.get("method", method)
                request_headers = value.get("headers", request_headers)
                request_body = value.get("body", request_body)
            elif isinstance(value, str):
                # If it's raw text
                lines = value.splitlines()
                if lines:
                    parts = lines[0].split()
                    if len(parts) >= 1:
                        method = parts[0]
    
    # Also fallback to physicalLocation uri properties if available
    locations = result.get("locations", [])
    if locations:
        loc = locations[0]
        phys = loc.get("physicalLocation", {})
        region = phys.get("region", {})
        # ZAP sometimes puts info in region properties
        if region:
            pass
            
    return method, request_headers, request_body

def ingest_sarif(input_path, output_path):
    print(f"Ingesting SARIF file: {input_path}")
    if not os.path.exists(input_path):
        print(f"Error: Input file does not exist: {input_path}", file=sys.stderr)
        sys.exit(1)
        
    try:
        with open(input_path, "r", encoding="utf-8") as f:
            sarif_data = json.load(f)
    except Exception as e:
        print(f"Error reading or parsing SARIF JSON: {e}", file=sys.stderr)
        sys.exit(1)
        
    runs = sarif_data.get("runs", [])
    findings = []
    finding_id = 1
    
    for run in runs:
        results = run.get("results", [])
        rules_map = {}
        
        # Load rules info to resolve nice rule names
        resources = run.get("tool", {}).get("driver", {}).get("rules", [])
        for rule in resources:
            r_id = rule.get("id")
            name = rule.get("shortDescription", {}).get("text", rule.get("name", r_id))
            rules_map[r_id] = name

        for result in results:
            rule_id = result.get("ruleId")
            rule_name = rules_map.get(rule_id, result.get("message", {}).get("text", rule_id))
            
            # Extract URL
            url = ""
            locations = result.get("locations", [])
            if locations:
                uri = locations[0].get("physicalLocation", {}).get("artifactLocation", {}).get("uri", "")
                url = uri
            
            if not url:
                # Fallback to general finding URI
                url = result.get("message", {}).get("text", "")
                if "http" not in url:
                    url = "http://127.0.0.1:5000"
            
            method, request_headers, request_body = extract_http_details(result)
            
            # Store in standardized format
            findings.append({
                "id": finding_id,
                "rule": rule_name,
                "url": url,
                "method": method,
                "request_headers": request_headers,
                "request_body": request_body
            })
            finding_id += 1
            
    # Save findings
    output_dir = os.path.dirname(output_path)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir, exist_ok=True)
        
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(findings, f, indent=2)
        
    print(f"Ingestion completed. Normalized {len(findings)} findings to {output_path}")

if __name__ == "__main__":
    args = parse_args()
    ingest_sarif(args.input, args.output)
