from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse
import requests
from bs4 import BeautifulSoup

DEFAULT_FIELD_VALUE = "test"


def _parse_page(html_content, page_url):
    soup = BeautifulSoup(html_content, "html.parser")
    links = []
    forms = []

    # 1. Parse all links
    for a in soup.find_all("a", href=True):
        links.append(urljoin(page_url, a["href"]))

    # 2. Parse all forms
    for form in soup.find_all("form"):
        action = form.get("action") or page_url
        method = (form.get("method") or "GET").upper()
        
        fields = {}
        for tag in form.find_all(["input", "textarea", "select"]):
            name = tag.get("name")
            if not name:
                continue
                
            field_type = (tag.get("type") or "text").lower()
            if field_type in {"button", "submit", "reset", "image", "file"}:
                continue
                
            fields[name] = tag.get("value") or DEFAULT_FIELD_VALUE
            
        forms.append({
            "action": action,
            "method": method,
            "fields": fields
        })
        
    return links, forms


def _same_origin(url, base):
    parsed_url = urlparse(url)
    parsed_base = urlparse(base)
    return (
        parsed_url.scheme in {"http", "https"}
        and parsed_url.netloc == parsed_base.netloc
    )


def _normalize_url(url):
    parsed = urlparse(url)
    return urlunparse(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path or "/",
            "",
            parsed.query,
            "",
        )
    )


def _with_query(url, params):
    parsed = urlparse(url)
    query = parse_qs(parsed.query)

    for key, value in params.items():
        query.setdefault(key, [value])

    return urlunparse(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path or "/",
            parsed.params,
            urlencode(query, doseq=True),
            parsed.fragment,
        )
    )


def _directory_urls(directory_result):
    if not isinstance(directory_result, dict):
        return []

    urls = []
    for finding in directory_result.get("findings", []):
        final_url = finding.get("final_url") or finding.get("url")
        if final_url:
            urls.append(final_url)

    return urls


def discover_injection_targets(
    target,
    directory_result=None,
    timeout=7,
    max_pages=40,
    verify_ssl=True,
):
    """
    Discover GET and POST targets that contain user-controlled parameters.
    Uses the base page plus URLs discovered by the directory scan.
    """
    pages_to_visit = [target, *_directory_urls(directory_result)]
    visited = set()
    get_targets = {}
    post_targets = {}
    errors = []

    result = {
        "status": "not_started",
        "pages_visited": 0,
        "get_targets": [],
        "post_targets": [],
        "errors": errors,
    }

    while pages_to_visit and len(visited) < max_pages:
        page_url = _normalize_url(pages_to_visit.pop(0))

        if page_url in visited or not _same_origin(page_url, target):
            continue

        visited.add(page_url)

        parsed_page = urlparse(page_url)
        if parsed_page.query:
            get_targets.setdefault(
                page_url,
                {"url": page_url, "source": "link_or_directory"},
            )

        try:
            response = requests.get(
                page_url,
                timeout=timeout,
                allow_redirects=True,
                verify=verify_ssl,
            )
        except Exception as error:
            errors.append({"url": page_url, "error": str(error)})
            continue

        content_type = response.headers.get("content-type", "")
        if "html" not in content_type.lower():
            continue

        links, forms = _parse_page(response.text, response.url)

        for link in links:
            if not _same_origin(link, target):
                continue

            normalized_link = _normalize_url(link)
            parsed_link = urlparse(normalized_link)

            if parsed_link.query:
                get_targets.setdefault(
                    normalized_link,
                    {"url": normalized_link, "source": page_url},
                )
            elif normalized_link not in visited and len(pages_to_visit) < max_pages:
                pages_to_visit.append(normalized_link)

        for form in forms:
            if not form["fields"]:
                continue

            action_url = _normalize_url(urljoin(response.url, form["action"]))
            if not _same_origin(action_url, target):
                continue

            if form["method"] == "POST":
                key = (action_url, tuple(sorted(form["fields"])))
                post_targets.setdefault(
                    key,
                    {
                        "url": action_url,
                        "method": "POST",
                        "data": form["fields"],
                        "source": page_url,
                    },
                )
            else:
                target_url = _with_query(action_url, form["fields"])
                get_targets.setdefault(
                    target_url,
                    {"url": target_url, "method": "GET", "source": page_url},
                )

    result["pages_visited"] = len(visited)
    result["get_targets"] = list(get_targets.values())
    result["post_targets"] = list(post_targets.values())
    result["status"] = (
        "injection_targets_found"
        if get_targets or post_targets
        else "no_injection_targets_found"
    )

    return result
