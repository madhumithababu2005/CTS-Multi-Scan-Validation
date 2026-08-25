import os
import json
import argparse
import sys

# Import ML prediction module
try:
    from ml.predict import run_ml_classification
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
    print("Warning: ML module not available. ML predictions will be disabled.", file=sys.stderr)

def parse_args():
    parser = argparse.ArgumentParser(description="Classify findings using Rule Engine and optional ML.")
    parser.add_argument(
        "--findings", 
        default="scans/scan_01/normalized_findings.json",
        help="Path to normalized_findings.json"
    )
    parser.add_argument(
        "--replay", 
        default="scans/scan_01/replay_results.json",
        help="Path to replay_results.json"
    )
    parser.add_argument(
        "--output", 
        default="scans/scan_01/classified_findings.json",
        help="Path to output classified_findings.json"
    )
    return parser.parse_args()

def run_classification(findings_path, replay_path, output_path):
    print(f"Loading findings and replay results...")
    
    if not os.path.exists(findings_path):
        print(f"Error: Findings file does not exist: {findings_path}", file=sys.stderr)
        sys.exit(1)
    if not os.path.exists(replay_path):
        print(f"Error: Replay file does not exist: {replay_path}", file=sys.stderr)
        sys.exit(1)
        
    try:
        with open(findings_path, "r", encoding="utf-8") as f:
            findings = json.load(f)
        with open(replay_path, "r", encoding="utf-8") as f:
            replay_results = json.load(f)
    except Exception as e:
        print(f"Error parsing input files: {e}", file=sys.stderr)
        sys.exit(1)
    
    # Run ML classification if available
    ml_results = {}
    ml_enabled = ML_AVAILABLE
    if ml_enabled:
        print("Running ML classification...")
        try:
            model_path = os.path.join(os.path.dirname(__file__), "ml", "model.pkl")
            ml_results = run_ml_classification(findings, replay_results, model_path)
            print("ML classification completed.")
        except Exception as e:
            print(f"Warning: ML classification failed: {e}. ML predictions will be disabled.", file=sys.stderr)
            ml_enabled = False
    else:
        print("ML classification skipped (ML module not available).")
        
    # Map replay results by ID for easy lookup
    replay_map = {r["id"]: r for r in replay_results}
    
    classified_findings = []
    
    for finding in findings:
        fid = finding["id"]
        rule = finding["rule"]
        url = finding["url"]
        
        replay_info = replay_map.get(fid)
        if not replay_info:
            print(f"Warning: No replay result found for finding ID {fid}. Skipping.", file=sys.stderr)
            continue
            
        replay_verdict = replay_info["verdict"]
        evidence = replay_info["reason"]
        
        # 1. Rule Engine Classification
        if replay_verdict == "reproduced":
            rule_classification = "true_positive"
            rule_confidence = 1.0
            rule_explanation = "The vulnerability was successfully reproduced against the live target application."
        elif replay_verdict == "not_reproduced":
            rule_classification = "false_positive"
            rule_confidence = 1.0
            rule_explanation = "Replay evidence showed that the expected security condition was not present on the live target."
        else:  # inconclusive
            rule_classification = "inconclusive"
            rule_confidence = 0.5
            rule_explanation = "Replay was inconclusive due to connection/protocol errors or unexpected response behavior."
            
        # 2. ML Classification
        if ml_enabled and fid in ml_results:
            ml_prediction, ml_confidence = ml_results[fid]
        else:
            ml_prediction = None
            ml_confidence = None
        
        # 3. Final Hybrid Decision
        final_classification = rule_classification
        
        if rule_classification == "true_positive":
            final_reason = "Replay evidence confirmed the security vulnerability is present."
        elif rule_classification == "false_positive":
            final_reason = "Replay evidence showed the expected security condition was not present."
        else:
            final_reason = "The replay result was inconclusive, so the finding cannot be reliably verified."
            
        classified_findings.append({
            "id": fid,
            "rule": rule,
            "url": url,
            "replay_verdict": replay_verdict,
            "evidence": evidence,
            "rule_classification": rule_classification,
            "rule_confidence": rule_confidence,
            "rule_explanation": rule_explanation,
            "ml_prediction": ml_prediction,
            "ml_confidence": ml_confidence,
            "final_classification": final_classification,
            "final_reason": final_reason
        })
        
    # Save output
    output_dir = os.path.dirname(output_path)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir, exist_ok=True)
        
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(classified_findings, f, indent=2)
        
    print(f"Classification completed. Saved to {output_path}")

if __name__ == "__main__":
    args = parse_args()
    run_classification(args.findings, args.replay, args.output)
