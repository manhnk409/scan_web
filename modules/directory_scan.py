import os
import time
from queue import Queue
from threading import Thread
from urllib.parse import urljoin

import requests

# Download the default wordlist if it doesn't exist

DEFAULT_WORDLIST = "common.txt"
DEFAULT_THREADS = 50
DEFAULT_TIMEOUT = 5
DEFAULT_EXTENSIONS = ["", ".asp", ".aspx", ".php", ".bak", ".txt", ".zip", ".config"]
INTERESTING_STATUS_CODES = {200, 301, 302, 403}

if not os.path.exists(DEFAULT_WORDLIST):
    print(f"Downloading default wordlist to {DEFAULT_WORDLIST}...")
    response = requests.get("https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt")
    with open(DEFAULT_WORDLIST, "wb") as f:
        f.write(response.content)

def _load_wordlist(wordlist):
    with open(wordlist, "r", encoding="utf-8", errors="ignore") as wordlist_file:
        return [
            line.strip().lstrip("/")
            for line in wordlist_file
            if line.strip() and not line.startswith("#")
        ]


def _build_url(target, path, extension):
    base_url = target.rstrip("/") + "/"
    candidate_path = f"{path}{extension}".lstrip("/")
    return urljoin(base_url, candidate_path)


def scan_directory(
    target,
    wordlist=DEFAULT_WORDLIST,
    threads=DEFAULT_THREADS,
    timeout=DEFAULT_TIMEOUT,
    extensions=None,
    verify_ssl=True,
):
    """
    Directory and file brute force check.
    Returns structured results for the HTML report.
    """
    started_at = time.time()
    extensions = extensions or DEFAULT_EXTENSIONS
    found = []
    errors = []
    queue = Queue()

    result = {
        "status": "not_started",
        "target_url": target,
        "wordlist": wordlist,
        "threads": threads,
        "extensions": extensions,
        "tested_paths": 0,
        "findings": found,
        "errors": errors,
        "duration_seconds": 0,
    }

    if not os.path.exists(wordlist):
        result["status"] = "wordlist_not_found"
        result["error"] = f"Wordlist not found: {wordlist}"
        return result

    try:
        words = _load_wordlist(wordlist)
    except Exception as error:
        result["status"] = "wordlist_read_failed"
        result["error"] = str(error)
        return result

    if not words:
        result["status"] = "empty_wordlist"
        return result

    def scan(url):
        try:
            response = requests.get(
                url,
                timeout=timeout,
                allow_redirects=True,
                verify=verify_ssl,
            )
        except Exception as error:
            errors.append({"url": url, "error": str(error)})
            return

        if response.status_code in INTERESTING_STATUS_CODES:
            finding = {
                "url": url,
                "status_code": response.status_code,
                "content_length": len(response.content),
            }

            if response.url != url:
                finding["final_url"] = response.url

            found.append(finding)
            print(f"[{response.status_code}] {url}")

    def worker():
        while True:
            path = queue.get()

            try:
                for extension in extensions:
                    scan(_build_url(target, path, extension))
            finally:
                queue.task_done()

    for _ in range(max(1, threads)):
        thread = Thread(target=worker, daemon=True)
        thread.start()

    for word in words:
        queue.put(word)

    queue.join()

    result["tested_paths"] = len(words) * len(extensions)
    result["duration_seconds"] = round(time.time() - started_at, 2)
    result["status"] = (
        "potential_paths_found"
        if found
        else "no_interesting_paths_found"
    )

    return result
