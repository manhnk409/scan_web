import requests
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse


XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    '"<svg onload=alert(1)>',
    "'><img src=x onerror=alert(1)>",
    "<iframe src=javascript:alert(1)>",
]


def scan_xss(url, method="GET", data=None, verify_ssl=True):
    """
    Simple reflected XSS check.
    Currently tests query parameters on GET requests.
    """
    parsed = urlparse(url)
    params = parse_qs(parsed.query) if method == "GET" else (data or {})

    result = {
        "status": "no_vulnerability_detected",
        "findings": [],
        "tested_parameters": [],
    }

    if not params:
        result["status"] = "no_parameters_found"
        return result

    try:
        if method == "GET":
            baseline_response = requests.get(url, timeout=10, verify=verify_ssl)
        else:
            baseline_response = requests.post(
                url,
                data=data,
                timeout=10,
                verify=verify_ssl,
            )
    except Exception as error:
        return {"status": "baseline_request_failed", "error": str(error), "findings": []}

    for parameter in params:
        original = params[parameter][0] if isinstance(params[parameter], list) else params[parameter]
        parameter_result = {"parameter": parameter, "payloads_tested": 0, "evidence": []}
        parameter_reflection = False

        for payload in XSS_PAYLOADS:
            test_params = params.copy()
            test_params[parameter] = original + payload

            try:
                if method == "GET":
                    test_url = urlunparse(
                        (
                            parsed.scheme,
                            parsed.netloc,
                            parsed.path,
                            parsed.params,
                            urlencode(test_params, doseq=True),
                            parsed.fragment,
                        )
                    )
                    response = requests.get(
                        test_url,
                        timeout=10,
                        verify=verify_ssl,
                    )
                else:
                    response = requests.post(
                        url,
                        data=test_params,
                        timeout=10,
                        verify=verify_ssl,
                    )

                parameter_result["payloads_tested"] += 1

                body = response.text
                if payload in body:
                    evidence = {"type": "raw_reflection", "payload": payload}
                    parameter_result["evidence"].append(evidence)
                    result["findings"].append(
                        {"parameter": parameter, "payload": payload, "details": [evidence]}
                    )
                    parameter_reflection = True
                elif original + payload in body:
                    evidence = {"type": "direct_reflection", "payload": payload}
                    parameter_result["evidence"].append(evidence)
                    result["findings"].append(
                        {"parameter": parameter, "payload": payload, "details": [evidence]}
                    )
                    parameter_reflection = True

            except Exception as error:
                parameter_result["evidence"].append({"payload": payload, "error": str(error)})

        result["tested_parameters"].append(parameter_result)
        if parameter_reflection:
            result["status"] = "input_reflection_observed"

    if result["status"] != "input_reflection_observed" and result["findings"]:
        result["status"] = "input_reflection_observed"

    return result
