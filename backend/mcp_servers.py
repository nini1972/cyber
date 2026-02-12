"""
Security analysis tools using semgrep CLI directly.
"""

import os
import json
import subprocess
import tempfile
from typing import Dict, Any, List


def run_semgrep_scan(code: str, filename: str = "analysis.py") -> Dict[str, Any]:
    """
    Run semgrep scan on the provided code using the CLI.

    Args:
        code: The Python code to analyze
        filename: The filename to use for the code (for better error messages)

    Returns:
        Dictionary containing semgrep scan results
    """
    # Trim whitespace/newlines to avoid invalid Authorization header formatting
    semgrep_app_token = os.getenv("SEMGREP_APP_TOKEN", "").strip()

    # Create a temporary file with the code
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(code)
        temp_file = f.name

    try:
        # Prepare environment
        env = os.environ.copy()
        if semgrep_app_token:
            env["SEMGREP_APP_TOKEN"] = semgrep_app_token

        # Run semgrep with auto config
        cmd = [
            "uvx",
            "--quiet",
            "semgrep",
            "scan",
            "--config",
            "auto",
            "--json",
            "--no-git-ignore",
            temp_file
        ]

        print(f"[DEBUG] Running semgrep scan: {' '.join(cmd)}")

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
            env=env
        )

        print(f"[DEBUG] Semgrep scan result:")
        print(f"[DEBUG]   Return code: {result.returncode}")
        print(f"[DEBUG]   Stdout length: {len(result.stdout)}")
        print(f"[DEBUG]   Stderr length: {len(result.stderr)}")

        # Log a short snippet of stderr for diagnostics (avoid flooding logs)
        stderr_snippet = (result.stderr or "")[:1000]
        if stderr_snippet:
            print(f"[DEBUG]   Stderr snippet: {stderr_snippet}")

        # Parse the JSON output
        if result.returncode == 0 and result.stdout:
            try:
                scan_results = json.loads(result.stdout)
                print(f"[DEBUG] Parsed {len(scan_results.get('results', []))} findings from semgrep")
                return {
                    "success": True,
                    "results": scan_results,
                    "findings_count": len(scan_results.get('results', []))
                }
            except json.JSONDecodeError as e:
                print(f"[DEBUG] Failed to parse semgrep JSON output: {e}")
                return {
                    "success": False,
                    "error": f"Failed to parse semgrep output: {str(e)}",
                    "stdout": result.stdout[:500],
                    "stderr": result.stderr[:500]
                }
        else:
            # Semgrep might return non-zero even if it found issues
            # Try to parse the output anyway
            if result.stdout:
                try:
                    scan_results = json.loads(result.stdout)
                    print(f"[DEBUG] Parsed {len(scan_results.get('results', []))} findings from semgrep (non-zero exit)")
                    return {
                        "success": True,
                        "results": scan_results,
                        "findings_count": len(scan_results.get('results', []))
                    }
                except json.JSONDecodeError:
                    pass

            print(f"[DEBUG] Semgrep scan failed or returned no results")
            return {
                "success": False,
                "error": "Semgrep scan failed",
                "return_code": result.returncode,
                "stdout": result.stdout[:500],
                "stderr": result.stderr[:2000]
            }

    except subprocess.TimeoutExpired:
        print(f"[DEBUG] Semgrep scan timed out after 120 seconds")
        return {
            "success": False,
            "error": "Semgrep scan timed out"
        }
    except Exception as e:
        print(f"[DEBUG] Semgrep scan failed: {type(e).__name__}: {str(e)}")
        return {
            "success": False,
            "error": f"Semgrep scan failed: {str(e)}"
        }
    finally:
        # Clean up the temporary file
        try:
            os.unlink(temp_file)
        except:
            pass


def format_semgrep_results_for_agent(scan_results: Dict[str, Any]) -> str:
    """
    Format semgrep scan results for the AI agent.

    Args:
        scan_results: The results from run_semgrep_scan

    Returns:
        Formatted string describing the findings
    """
    if not scan_results.get("success"):
        details = []
        err = scan_results.get('error', 'Unknown error')
        details.append(f"Semgrep scan failed: {err}")
        rc = scan_results.get('return_code')
        if rc is not None:
            details.append(f"return_code={rc}")
        stderr = scan_results.get('stderr')
        if stderr:
            details.append(f"stderr: {stderr[:500]}")
        stdout = scan_results.get('stdout')
        if stdout:
            details.append(f"stdout: {stdout[:200]}")
        return " | ".join(details)

    results = scan_results.get("results", {})
    findings = results.get("results", [])
    findings_count = scan_results.get("findings_count", 0)

    if findings_count == 0:
        return "Semgrep scan completed successfully but found no security issues."

    output = [f"Semgrep found {findings_count} security issue(s):\n"]

    for i, finding in enumerate(findings, 1):
        check_id = finding.get("check_id", "unknown")
        message = finding.get("message", "No message")
        severity = finding.get("extra", {}).get("severity", "UNKNOWN")
        cwe = finding.get("extra", {}).get("metadata", {}).get("cwe", [])

        # Get the code snippet
        code_snippet = ""
        if "paths" in finding and len(finding["paths"]) > 0:
            path_info = finding["paths"][0]
            if "snippet" in path_info:
                code_snippet = path_info["snippet"]["text"]

        output.append(f"\n{i}. {check_id} (Severity: {severity})")
        output.append(f"   Message: {message}")
        if cwe:
            output.append(f"   CWE: {', '.join(str(c) for c in cwe)}")
        if code_snippet:
            output.append(f"   Code:\n   {code_snippet}")

    return "\n".join(output)
