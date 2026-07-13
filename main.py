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


def run_scan(target, insecure=False, log_callback=None):
    verify_ssl = not insecure

    if insecure:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def log(message, step=None, status=None):
        if log_callback:
            log_callback(message, step, status)
        else:
            print(message)

    report = {}

    log("[+] Security Headers", step="headers", status="running")
    try:
        report["headers"] = scan_headers(target, verify_ssl=verify_ssl)
        log(f"Headers finished.", step="headers", status="success")
    except Exception as e:
        report["headers"] = {"error": str(e)}
        log(f"Headers check failed: {str(e)}", step="headers", status="failed")

    log("[+] SSL/TLS", step="ssl", status="running")
    try:
        report["ssl"] = scan_ssl(target, verify_ssl=verify_ssl)
        log(f"SSL/TLS finished.", step="ssl", status="success")
    except Exception as e:
        report["ssl"] = {"error": str(e)}
        log(f"SSL check failed: {str(e)}", step="ssl", status="failed")

    log("[+] Nmap", step="nmap", status="running")
    try:
        report["nmap"] = scan_nmap(target)
        log(f"Nmap scan finished.", step="nmap", status="success")
    except Exception as e:
        report["nmap"] = {"error": str(e)}
        log(f"Nmap scan failed: {str(e)}", step="nmap", status="failed")

    log("[+] Directory Brute Force", step="directory", status="running")
    try:
        report["directory"] = scan_directory(target, verify_ssl=verify_ssl)
        log(f"Directory scan finished. Discovered {len(report['directory'].get('findings', []))} paths.", step="directory", status="success")
    except Exception as e:
        report["directory"] = {"error": str(e), "status": "failed"}
        log(f"Directory scan failed: {str(e)}", step="directory", status="failed")

    log("[+] Discover Injection Targets", step="discovery", status="running")
    try:
        report["target_discovery"] = discover_injection_targets(
            target,
            report["directory"],
            verify_ssl=verify_ssl,
        )
        get_targets = report["target_discovery"]["get_targets"]
        post_targets = report["target_discovery"]["post_targets"]
        log(f"Injection target discovery finished. Found {len(get_targets)} GET and {len(post_targets)} POST targets.", step="discovery", status="success")
    except Exception as e:
        report["target_discovery"] = {"error": str(e), "get_targets": [], "post_targets": [], "status": "failed"}
        get_targets = []
        post_targets = []
        log(f"Target discovery failed: {str(e)}", step="discovery", status="failed")

    injection_targets = [
        {"method": "GET", **scan_target}
        for scan_target in get_targets
    ] + [
        {"method": "POST", **scan_target}
        for scan_target in post_targets
    ]

    log("[+] SQL Injection Check", step="sqli", status="running")
    sqli_results = []
    try:
        for scan_target in injection_targets[:MAX_SQLI_TARGETS]:
            log(f"    SQLi target: {scan_target['url']}")
            if scan_target["method"] == "POST":
                sqli_results.append(
                    scan_sqli(
                        scan_target["url"],
                        method="POST",
                        data=scan_target["data"],
                        timeout=SQLI_TIMEOUT_SECONDS,
                        insecure=insecure,
                    )
                )
            else:
                sqli_results.append(
                    scan_sqli(
                        scan_target["url"],
                        timeout=SQLI_TIMEOUT_SECONDS,
                        insecure=insecure,
                    )
                )
        report["sqli"] = _merge_sqli_results(sqli_results)
        report["sqli"]["skipped_targets"] = injection_targets[MAX_SQLI_TARGETS:]
        log(f"SQL injection check finished. Vulnerability status: {report['sqli'].get('status')}.", step="sqli", status="success")
    except Exception as e:
        report["sqli"] = {"error": str(e), "status": "failed"}
        log(f"SQL injection check failed: {str(e)}", step="sqli", status="failed")

    log("[+] XSS Check", step="xss", status="running")
    xss_results = []
    try:
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
        log(f"XSS check finished. Reflection status: {report['xss'].get('status')}.", step="xss", status="success")
    except Exception as e:
        report["xss"] = {"error": str(e), "status": "failed"}
        log(f"XSS check failed: {str(e)}", step="xss", status="failed")

    log("[+] Generating Report", step="report", status="running")
    try:
        html_path, json_path = generate_report(target, report)
        log(f"Report saved: {html_path}", step="report", status="success")
        return report, html_path, json_path
    except Exception as e:
        log(f"Failed to generate report: {str(e)}", step="report", status="failed")
        raise e


if __name__ == "__main__":
    args = _parse_args()
    target = args.target
    if not target:
        target = input("Nhap URL (vd: https://example.com): ")
        if not args.insecure:
            insecure_answer = input("Bo qua kiem tra SSL? (y/N): ").strip().lower()
            args.insecure = insecure_answer in {"y", "yes"}

    run_scan(target, insecure=args.insecure)
