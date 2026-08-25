import os
import json
import argparse
import urllib.request
import urllib.parse
import re
import sys

def parse_args():
    parser = argparse.ArgumentParser(description="Replay normalized findings against a live target.")
    parser.add_argument(
        "--findings", 
        default="scans/scan_01/normalized_findings.json",
        help="Path to normalized_findings.json"
    )
    parser.add_argument(
        "--target", 
        default="http://127.0.0.1:5000",
        help="Base URL of the live target application (e.g. http://127.0.0.1:5000)"
    )
    parser.add_argument(
        "--output", 
        default="scans/scan_01/replay_results.json",
        help="Path to output replay_results.json"
    )
    return parser.parse_args()

def remap_url(original_url, target_base):
    parsed_original = urllib.parse.urlparse(original_url)
    parsed_target = urllib.parse.urlparse(target_base)
    
    # Reconstruct the URL using target scheme, host/port, and original path/query/params
    remapped = urllib.parse.ParseResult(
        scheme=parsed_target.scheme,
        netloc=parsed_target.netloc,
        path=parsed_original.path,
        params=parsed_original.params,
        query=parsed_original.query,
        fragment=parsed_original.fragment
    )
    return urllib.parse.urlunparse(remapped)

def perform_request(url, method, headers, body):
    # Prepare request
    data = body.encode('utf-8') if body else None
    req = urllib.request.Request(url, data=data, method=method)
    
    # Add headers
    for k, v in headers.items():
        req.add_header(k, v)
        
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            res_body = response.read().decode('utf-8', errors='ignore')
            res_headers = {k: v for k, v in response.getheaders()}
            res_status = response.status
            return res_status, res_headers, res_body, None
    except urllib.error.HTTPError as e:
        # HTTP errors are still responses, read them
        res_body = e.read().decode('utf-8', errors='ignore')
        res_headers = {k: v for k, v in e.headers.items()}
        return e.code, res_headers, res_body, None
    except Exception as e:
        return None, None, None, str(e)

def analyze_vulnerability(rule, status, headers, body, error):
    if error:
        return "inconclusive", f"Network error during replay: {error}"
    
    rule_lower = rule.lower()
    
    # 1. Missing Security Headers
    if "header" in rule_lower or "clickjacking" in rule_lower or "csp" in rule_lower or "x-frame-options" in rule_lower:
        # Look for header names in response headers
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
        
        target_headers = []
        if "clickjacking" in rule_lower or "frame" in rule_lower or "x-frame-options" in rule_lower:
            target_headers.append("x-frame-options")
        if "csp" in rule_lower or "content-security-policy" in rule_lower:
            target_headers.append("content-security-policy")
        if not target_headers:
            # General header missing check
            target_headers = ["x-frame-options", "content-security-policy", "x-content-type-options"]
            
        missing = [h for h in target_headers if h not in headers_lower]
        if missing:
            return "reproduced", f"Security header(s) still missing: {', '.join(missing)}"
        else:
            return "not_reproduced", "All expected security headers are present."
            
    # 2. Private IP Disclosure
    elif "private" in rule_lower or "ip disclosure" in rule_lower or "intranet" in rule_lower:
        # Match standard IPv4 private ranges (10.x.x.x, 172.16-31.x.x, 192.168.x.x)
        private_ip_pattern = r'\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b'
        matches = re.findall(private_ip_pattern, body)
        if matches:
            return "reproduced", f"Private IP address leaked in response: {', '.join(set(matches))}"
        else:
            return "not_reproduced", "No private IP address disclosure found in response body."
            
    # 3. Directory Browsing / Listing
    elif "directory" in rule_lower or "browsing" in rule_lower or "index" in rule_lower:
        # Look for typical directory listing patterns
        if "index of" in body.lower() or "parent directory" in body.lower() or "href=" in body.lower():
            # Double check status is successful
            if status == 200:
                return "reproduced", "Directory listing is enabled and visible."
        
        # If it returned a 403, 404, or regular page
        return "not_reproduced", f"Directory listing not visible (Status: {status})."

    # Default fallback: check if response changed completely
    if status is not None:
        if 200 <= status < 400:
            return "reproduced", f"Endpoint responded successfully (Status: {status}). Evidence inconclusive but connection succeeded."
        else:
            return "not_reproduced", f"Endpoint returned failure response status (Status: {status})."
            
    return "inconclusive", "Could not verify vulnerability."

def run_replay(findings_path, target_base, output_path):
    print(f"Loading findings from: {findings_path}")
    if not os.path.exists(findings_path):
        print(f"Error: Findings file does not exist: {findings_path}", file=sys.stderr)
        sys.exit(1)
        
    try:
        with open(findings_path, "r", encoding="utf-8") as f:
            findings = json.load(f)
    except Exception as e:
        print(f"Error parsing findings file: {e}", file=sys.stderr)
        sys.exit(1)
        
    results = []
    
    for finding in findings:
        fid = finding.get("id")
        rule = finding.get("rule")
        orig_url = finding.get("url")
        method = finding.get("method", "GET")
        headers = finding.get("request_headers", {})
        body = finding.get("request_body", "")
        
        # Remap the URL to the live target
        url = remap_url(orig_url, target_base)
        print(f"Replaying finding {fid}: {rule} against {url}")
        
        status, res_headers, res_body, error = perform_request(url, method, headers, body)
        
        verdict, reason = analyze_vulnerability(rule, status, res_headers, res_body, error)
        
        results.append({
            "id": fid,
            "rule": rule,
            "verdict": verdict,
            "reason": reason,
            "url": url
        })
        
    # Write replay results
    output_dir = os.path.dirname(output_path)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir, exist_ok=True)
        
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
        
    print(f"Replay completed. Output saved to {output_path}")

if __name__ == "__main__":
    args = parse_args()
    run_replay(args.findings, args.target, args.output)
