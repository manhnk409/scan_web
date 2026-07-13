import shutil
import subprocess
import re
import json
from urllib.parse import parse_qs, urlencode, urlparse


def _parse_sqlmap_output(raw_output):
    findings = []

    parameter_pattern = re.compile(
        r"^Parameter:\s*(?P<parameter>.+?)\s*\((?P<location>[^)]+)\)\s*$"
        r"(?P<body>.*?)(?=^Parameter:\s*|\Z)",
        re.MULTILINE | re.DOTALL,
    )
    technique_pattern = re.compile(
        r"^\s*Type:\s*(?P<type>[^\n]+)\s*$\n"
        r"^\s*Title:\s*(?P<title>[^\n]+)\s*$\n"
        r"^\s*Payload:\s*(?P<payload>[^\n]+)\s*$",
        re.MULTILINE,
    )

    for parameter_match in parameter_pattern.finditer(raw_output):
        parameter_name = parameter_match.group("parameter").strip()
        location = parameter_match.group("location").strip()
        body = parameter_match.group("body")
        techniques = []

        for technique_match in technique_pattern.finditer(body):
            techniques.append({
                "type": technique_match.group("type").strip(),
                "title": technique_match.group("title").strip(),
                "payload": technique_match.group("payload").strip(),
            })

        if techniques:
            findings.append({
                "parameter": parameter_name,
                "location": location,
                "techniques": techniques,
            })

    return findings

def scan_sqli(
    url,
    method="GET",
    data=None,
    json_data=None,
    timeout=120,
    level=1,
    risk=1,
    insecure=False,
):
    """
    method: "GET" hoặc "POST"
    data: dict cho form POST
    json_data: dict cho JSON body
    """
    parsed = urlparse(url)
    url_params = list(parse_qs(parsed.query).keys())
    body_params = list((data or {}).keys())
    json_params = list((json_data or {}).keys()) if isinstance(json_data, dict) else []
    target_params = list(dict.fromkeys(url_params + body_params + json_params))

    sqlmap_path = shutil.which("sqlmap")
    if not sqlmap_path:
        return {
            "status": "sqlmap_not_found",
            "error": "sqlmap is not installed or not in PATH",
            "target_url": url,
            "target_parameters": target_params,
            "confirmed_findings": [],
            "findings": [],
            "tested_parameters": [],
        }

    cmd = [
        sqlmap_path,
        "-u",
        url,
        "--batch",
        f"--level={level}",
        f"--risk={risk}",
    ]

    if method == "POST" and data:
        cmd += ["--data", urlencode(data)]

    if json_data:
        cmd += ["--data", json.dumps(json_data)]

    if target_params:
        cmd += ["-p", ",".join(target_params)]

    if insecure:
        cmd += ["--ignore-ssl-errors"]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as error:
        out = ""
        if error.stdout:
            out += error.stdout if isinstance(error.stdout, str) else error.stdout.decode(errors="ignore")
        if error.stderr:
            out += "\n" + (
                error.stderr
                if isinstance(error.stderr, str)
                else error.stderr.decode(errors="ignore")
            )

        return {
            "status": "scan_timeout",
            "error": f"sqlmap timed out after {timeout} seconds",
            "target_url": url,
            "target_parameters": target_params,
            "confirmed_findings": [],
            "findings": [
                {"parameter": p, "notes": "sqlmap timed out before completion"}
                for p in target_params
            ],
            "tested_parameters": [
                {"parameter": p, "payloads_tested": "sqlmap-managed", "evidence": [{"error": "timeout"}]}
                for p in target_params
            ],
            "raw_output": out,
        }

    out = proc.stdout + "\n" + proc.stderr
    low = out.lower()
    confirmed_findings = _parse_sqlmap_output(out)
    status = "sqlmap_run"

    if confirmed_findings:
        status = "potential_vulnerability_detected"

    if "not appear to be injectable" in low or "do not appear to be injectable" in low:
        status = "no_vulnerability_detected"
    elif "appear to be injectable" in low or "is vulnerable" in low:
        status = "potential_vulnerability_detected"

    return {
        "status": status,
        "target_url": url,
        "target_parameters": target_params,
        "confirmed_findings": confirmed_findings,
        "findings": [{"parameter": p, "notes": "submitted to sqlmap"} for p in target_params],
        "tested_parameters": [{"parameter": p, "payloads_tested": "sqlmap-managed"} for p in target_params],
        "raw_output": out,
    }
