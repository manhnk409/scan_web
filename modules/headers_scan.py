import requests


SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]


def scan_headers(url, verify_ssl=True):
    result = {}

    try:
        response = requests.get(
            url,
            timeout=10,
            verify=verify_ssl,
        )

        for header in SECURITY_HEADERS:
            result[header] = header in response.headers

        return result

    except Exception as error:
            return {"error": str(error)}
