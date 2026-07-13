from modules.headers_scan import scan_headers
from modules.ssl_scan import scan_ssl
from modules.nmap_scan import scan_nmap
from modules.report import generate_report
from modules.sqli_scan import scan_sqli
from modules.xss_scan import scan_xss
from modules.directory_scan import scan_directory
from modules.target_discovery import discover_injection_targets
import argparse
import urllib3


MAX_SQLI_TARGETS = 5
SQLI_TIMEOUT_SECONDS = 120


def _summarize_status(results, vulnerable_statuses):
    statuses = [result.get("status") for result in results]

    if not results:
        return "no_parameters_found"

    if any(status in vulnerable_statuses for status in statuses):
        return next(status for status in statuses if status in vulnerable_statuses)

    if any(status == "sqlmap_not_found" for status in statuses):
        return "sqlmap_not_found"

    if any(status == "baseline_request_failed" for status in statuses):
        return "baseline_request_failed"

    if any(status == "scan_timeout" for status in statuses):
        return "scan_timeout"

    return "no_vulnerability_detected"


def _merge_sqli_results(results):
    merged = {
        "status": _summarize_status(results, {"potential_vulnerability_detected"}),
        "target_url": "auto-discovered targets",
        "target_parameters": [],
        "confirmed_findings": [],
        "findings": [],
        "tested_parameters": [],
        "raw_output": "",
        "scan_results": results,
    }

    for result in results:
        target_url = result.get("target_url", "")

        for parameter in result.get("target_parameters", []):
            if parameter not in merged["target_parameters"]:
                merged["target_parameters"].append(parameter)

        for finding in result.get("confirmed_findings", []):
            finding = dict(finding)
            finding["target_url"] = target_url
            merged["confirmed_findings"].append(finding)

        for finding in result.get("findings", []):
            finding = dict(finding)
            finding["target_url"] = target_url
            merged["findings"].append(finding)

        for item in result.get("tested_parameters", []):
            item = dict(item)
            item["target_url"] = target_url
            merged["tested_parameters"].append(item)

        if result.get("raw_output"):
            merged["raw_output"] += f"\n\n### {target_url}\n{result['raw_output']}"

    return merged


def _merge_xss_results(results):
    merged = {
        "status": _summarize_status(results, {"input_reflection_observed"}),
        "findings": [],
        "tested_parameters": [],
        "scan_results": results,
    }

    for result in results:
        target_url = result.get("target_url", "")

        for finding in result.get("findings", []):
            finding = dict(finding)
            finding["target_url"] = target_url
            merged["findings"].append(finding)

        for item in result.get("tested_parameters", []):
            item = dict(item)
            item["target_url"] = target_url
            merged["tested_parameters"].append(item)

    return merged

def _parse_args():
    parser = argparse.ArgumentParser(description="Simple web security scanner")
    parser.add_argument("target", nargs="?", help="Target URL, e.g. https://example.com")
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Skip SSL certificate verification for lab targets with invalid certificates",
    )
    return parser.parse_args()


args = _parse_args()
target = args.target
if not target:
    target = input("Nhap URL (vd: https://example.com): ")
    if not args.insecure:
        insecure_answer = input("Bo qua kiem tra SSL? (y/N): ").strip().lower()
        args.insecure = insecure_answer in {"y", "yes"}

verify_ssl = not args.insecure

if args.insecure:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

report = {}

print("[+] Security Headers")
report["headers"] = scan_headers(target, verify_ssl=verify_ssl)

print("[+] SSL/TLS")
report["ssl"] = scan_ssl(target, verify_ssl=verify_ssl)

print("[+] Nmap")
report["nmap"] = scan_nmap(target)

print("[+] Directory Brute Force")
report["directory"] = scan_directory(target, verify_ssl=verify_ssl)

print("[+] Discover Injection Targets")
report["target_discovery"] = discover_injection_targets(
    target,
    report["directory"],
    verify_ssl=verify_ssl,
)
get_targets = report["target_discovery"]["get_targets"]
post_targets = report["target_discovery"]["post_targets"]
injection_targets = [
    {"method": "GET", **scan_target}
    for scan_target in get_targets
] + [
    {"method": "POST", **scan_target}
    for scan_target in post_targets
]

print("[+] SQL Injection Check")
sqli_results = []
for scan_target in injection_targets[:MAX_SQLI_TARGETS]:
    print(f"    SQLi target: {scan_target['url']}")
    if scan_target["method"] == "POST":
        sqli_results.append(
            scan_sqli(
                scan_target["url"],
                method="POST",
                data=scan_target["data"],
                timeout=SQLI_TIMEOUT_SECONDS,
                insecure=args.insecure,
            )
        )
    else:
        sqli_results.append(
            scan_sqli(
                scan_target["url"],
                timeout=SQLI_TIMEOUT_SECONDS,
                insecure=args.insecure,
            )
        )
report["sqli"] = _merge_sqli_results(sqli_results)
report["sqli"]["skipped_targets"] = injection_targets[MAX_SQLI_TARGETS:]

print("[+] XSS Check")
xss_results = []
for scan_target in get_targets:
    result = scan_xss(scan_target["url"], verify_ssl=verify_ssl)
    result["target_url"] = scan_target["url"]
    xss_results.append(result)
for scan_target in post_targets:
    result = scan_xss(
        scan_target["url"],
        method="POST",
        data=scan_target["data"],
        verify_ssl=verify_ssl,
    )
    result["target_url"] = scan_target["url"]
    xss_results.append(result)
report["xss"] = _merge_xss_results(xss_results)


generate_report(target, report)

print("Report saved.")
