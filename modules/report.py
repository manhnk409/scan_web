from datetime import datetime
from html import escape
import os


def _render_pretty_block(value):
    return f"<pre>{escape(repr(value))}</pre>"


def _render_status(status):
    labels = {
        "potential_vulnerability_detected": "Phát hiện nguy cơ lỗ hổng",
        "input_reflection_observed": "Phát hiện phản chiếu đầu vào",
        "no_parameters_found": "Không tìm thấy tham số",
        "no_vulnerability_detected": "Không phát hiện lỗ hổng rõ ràng",
        "baseline_request_failed": "Yêu cầu cơ bản thất bại",
        "sqlmap_run": "Đã chạy sqlmap",
        "potential_paths_found": "Tìm thấy đường dẫn tiềm năng",
        "no_interesting_paths_found": "Không tìm thấy đường dẫn quan trọng",
        "wordlist_not_found": "Không tìm thấy danh sách từ khóa",
        "wordlist_read_failed": "Đọc danh sách từ khóa thất bại",
        "empty_wordlist": "Danh sách từ khóa rỗng",
        "injection_targets_found": "Tìm thấy mục tiêu tiêm",
        "no_injection_targets_found": "Không tìm thấy mục tiêu tiêm",
        "sqlmap_not_found": "Không tìm thấy sqlmap",
        "scan_timeout": "Quét vượt thời gian",
    }

    return labels.get(status, status or "unknown")

def _render_detail_list(details):
    if not isinstance(details, list):
        return ""

    parts = []
    for detail in details:
        if isinstance(detail, dict):
            parts.append(
                ", ".join(
                    f"{key}={escape(str(value))}"
                    for key, value in detail.items()
                )
            )
        else:
            parts.append(escape(str(detail)))

    return ", ".join(parts)


def _render_directory_section(directory):
    if not isinstance(directory, dict):
        return f"<pre>{escape(repr(directory))}</pre>"

    status = directory.get("status", "unknown")
    findings = directory.get("findings", [])
    errors = directory.get("errors", [])
    extensions = directory.get("extensions", [])

    html_parts = [
        "<section>",
        "<h2>Danh Mục Brute Force</h2>",
        f"<p><strong>Trạng thái:</strong> {escape(_render_status(status))}</p>",
        f"<p><strong>Danh sách từ khóa:</strong> {escape(str(directory.get('wordlist', '')))}</p>",
        f"<p><strong>Số luồng:</strong> {escape(str(directory.get('threads', '')))}</p>",
        f"<p><strong>Đường dẫn đã thử:</strong> {escape(str(directory.get('tested_paths', 0)))}</p>",
        f"<p><strong>Số phát hiện:</strong> {len(findings)}</p>",
        f"<p><strong>Thời gian:</strong> {escape(str(directory.get('duration_seconds', 0)))} giây</p>",
    ]

    if directory.get("error"):
        html_parts.append(
            f"<p><strong>Lỗi:</strong> {escape(str(directory.get('error')))}</p>"
        )

    if extensions:
        html_parts.append(
            f"<p><strong>Đuôi tệp:</strong> {escape(', '.join(map(str, extensions)))}</p>"
        )

    if findings:
        html_parts.append("<h3>Đường dẫn tiềm năng</h3>")
        html_parts.append("<table border='1' cellspacing='0' cellpadding='6'>")
        html_parts.append(
            "<tr>"
            "<th>Mã trạng thái</th>"
            "<th>URL</th>"
            "<th>URL cuối</th>"
            "<th>Kích thước nội dung</th>"
            "</tr>"
        )

        for finding in findings:
            html_parts.append(
                "<tr>"
                f"<td>{escape(str(finding.get('status_code', '')))}</td>"
                f"<td>{escape(str(finding.get('url', '')))}</td>"
                f"<td>{escape(str(finding.get('final_url', '')))}</td>"
                f"<td>{escape(str(finding.get('content_length', '')))}</td>"
                "</tr>"
            )

        html_parts.append("</table>")

    if errors:
        html_parts.append("<details>")
        html_parts.append(f"<summary>Request errors ({len(errors)})</summary>")
        html_parts.append(f"<pre>{escape(repr(errors[:50]))}</pre>")
        html_parts.append("</details>")

    html_parts.append("</section>")
    return "\n".join(html_parts)


def _render_target_discovery_section(discovery):
    if not isinstance(discovery, dict):
        return f"<pre>{escape(repr(discovery))}</pre>"

    get_targets = discovery.get("get_targets", [])
    post_targets = discovery.get("post_targets", [])
    errors = discovery.get("errors", [])

    html_parts = [
        "<section>",
        "<h2>Khám phá mục tiêu tiêm</h2>",
        f"<p><strong>Trạng thái:</strong> {escape(_render_status(discovery.get('status', 'unknown')))}</p>",
        f"<p><strong>Số trang đã duyệt:</strong> {escape(str(discovery.get('pages_visited', 0)))}</p>",
        f"<p><strong>Mục tiêu GET:</strong> {len(get_targets)}</p>",
        f"<p><strong>Mục tiêu POST:</strong> {len(post_targets)}</p>",
    ]

    if get_targets:
        html_parts.append("<h3>Mục tiêu GET</h3>")
        html_parts.append("<table border='1' cellspacing='0' cellpadding='6'>")
        html_parts.append("<tr><th>URL</th><th>Nguồn</th></tr>")

        for item in get_targets:
            html_parts.append(
                "<tr>"
                f"<td>{escape(str(item.get('url', '')))}</td>"
                f"<td>{escape(str(item.get('source', '')))}</td>"
                "</tr>"
            )

        html_parts.append("</table>")

    if post_targets:
        html_parts.append("<h3>Mục tiêu POST</h3>")
        html_parts.append("<table border='1' cellspacing='0' cellpadding='6'>")
        html_parts.append("<tr><th>URL</th><th>Trường</th><th>Nguồn</th></tr>")

        for item in post_targets:
            html_parts.append(
                "<tr>"
                f"<td>{escape(str(item.get('url', '')))}</td>"
                f"<td>{escape(', '.join(item.get('data', {}).keys()))}</td>"
                f"<td>{escape(str(item.get('source', '')))}</td>"
                "</tr>"
            )

        html_parts.append("</table>")

    if errors:
        html_parts.append("<details>")
        html_parts.append(f"<summary>Lỗi khám phá ({len(errors)})</summary>")
        html_parts.append(f"<pre>{escape(repr(errors[:50]))}</pre>")
        html_parts.append("</details>")

    html_parts.append("</section>")
    return "\n".join(html_parts)


def _render_sqlmap_section(sqli):
    status = sqli.get("status", "unknown")
    target_url = sqli.get("target_url", "")
    target_parameters = sqli.get("target_parameters", [])
    findings = sqli.get("findings", [])
    confirmed_findings = sqli.get("confirmed_findings", [])
    tested_parameters = sqli.get("tested_parameters", [])
    raw_output = sqli.get("raw_output", "")
    skipped_targets = sqli.get("skipped_targets", [])

    html_parts = [
        "<section>",
        "<h2>Kiểm tra SQL Injection</h2>",
        f"<p><strong>Trạng thái:</strong> {escape(_render_status(status))}</p>",
    ]

    if target_url:
        html_parts.append(
            f"<p><strong>URL Mục tiêu:</strong> "
            f"{escape(str(target_url))}</p>"
        )

    if target_parameters:
        html_parts.append(
            f"<p><strong>Tham số mục tiêu:</strong> "
            f"{escape(', '.join(map(str, target_parameters)))}</p>"
        )

    if skipped_targets:
        html_parts.append(
            f"<p><strong>Đã bỏ qua mục tiêu SQLi:</strong> "
            f"{len(skipped_targets)} do giới hạn quét</p>"
        )
        html_parts.append("<details>")
        html_parts.append("<summary>Danh sách mục tiêu bị bỏ qua</summary>")
        html_parts.append("<ul>")
        for item in skipped_targets:
            html_parts.append(
                f"<li>{escape(str(item.get('method', 'GET')))} "
                f"{escape(str(item.get('url', '')))}</li>"
            )
        html_parts.append("</ul>")
        html_parts.append("</details>")

    if tested_parameters:
        html_parts.append(
            f"<p><strong>Tham số đã thử:</strong> "
            f"{len(tested_parameters)}</p>"
        )

        html_parts.append("<h3>Tham số đã thử</h3>")
        html_parts.append(
            "<table border='1' cellspacing='0' cellpadding='6'>"
        )
        show_target_url = any(item.get("target_url") for item in tested_parameters)

        html_parts.append("<tr>")
        if show_target_url:
            html_parts.append("<th>URL mục tiêu</th>")
        html_parts.append(
            "<th>Tham số</th>"
            "<th>Số payload đã thử</th>"
            "<th>Số bằng chứng</th>"
            "</tr>"
        )

        for item in tested_parameters:
            evidence_count = (
                len(item.get("evidence", []))
                if isinstance(item.get("evidence", []), list)
                else 0
            )

            html_parts.append("<tr>")
            if show_target_url:
                html_parts.append(f"<td>{escape(str(item.get('target_url', '')))}</td>")
            html_parts.append(
                f"<td>{escape(str(item.get('parameter', '')))}</td>"
                f"<td>{escape(str(item.get('payloads_tested', 0)))}</td>"
                f"<td>{evidence_count}</td>"
                "</tr>"
            )

        html_parts.append("</table>")

    if confirmed_findings:
        html_parts.append(
            f"<p><strong>SQLi đã xác nhận:</strong> "
            f"{len(confirmed_findings)}</p>"
        )

        html_parts.append("<h3>SQLi đã xác nhận</h3>")
        html_parts.append(
            "<table border='1' cellspacing='0' cellpadding='6'>"
        )

        html_parts.append(
            "<tr>"
            "<th>URL mục tiêu</th>"
            "<th>Tham số</th>"
            "<th>Vị trí</th>"
            "<th>Kỹ thuật</th>"
            "<th>Tiêu đề</th>"
            "<th>Payload</th>"
            "</tr>"
        )

        for item in confirmed_findings:
            target_url = escape(str(item.get("target_url", "")))
            parameter = escape(str(item.get("parameter", "")))
            location = escape(str(item.get("location", "")))
            techniques = item.get("techniques", [])

            if not techniques:
                html_parts.append(
                    "<tr>"
                    f"<td>{target_url}</td>"
                    f"<td>{parameter}</td>"
                    f"<td>{location}</td>"
                    "<td colspan='3'>No technique details parsed</td>"
                    "</tr>"
                )
                continue

            first_row = True

            for technique in techniques:
                technique_type = escape(
                    str(technique.get("type", ""))
                )

                title = escape(
                    str(technique.get("title", ""))
                )

                payload = escape(
                    str(technique.get("payload", ""))
                )

                html_parts.append(
                    "<tr>"
                    + (
                        f"<td>{target_url}</td>"
                        f"<td>{parameter}</td>"
                        f"<td>{location}</td>"
                        if first_row
                        else "<td></td><td></td><td></td>"
                    )
                    + f"<td>{technique_type}</td>"
                    + f"<td>{title}</td>"
                    + f"<td>{payload}</td>"
                    + "</tr>"
                )

                first_row = False

        html_parts.append("</table>")

    elif findings:
        html_parts.append(
            f"<p><strong>Kết quả:</strong> "
            f"{len(findings)}</p>"
        )

        html_parts.append("<h3>Kết quả</h3>")
        html_parts.append("<ul>")

        for finding in findings:
            parameter = escape(
                str(finding.get("parameter", ""))
            )

            payload = finding.get("payload")
            notes = finding.get("notes")
            details = finding.get("details", [])

            line = f"<li><strong>{parameter}</strong>"
            target_url = finding.get("target_url")

            if target_url:
                line += f" trên {escape(str(target_url))}"

            if payload not in (None, ""):
                line += (
                    f" với payload "
                    f"<code>{escape(str(payload))}</code>"
                )

            if notes:
                line += f": {escape(str(notes))}"
            elif details:
                line += (
                    f": {_render_detail_list(details)}"
                )

            line += "</li>"
            html_parts.append(line)

        html_parts.append("</ul>")

    else:
        html_parts.append(
            "<p>Không có kết quả nào được báo bởi sqlmap.</p>"
        )

    if raw_output:
        html_parts.append("<details>")
        html_parts.append(
            "<summary>Xuất kết quả thô của sqlmap</summary>"
        )
        html_parts.append(
            f"<pre>{escape(raw_output)}</pre>"
        )
        html_parts.append("</details>")

    html_parts.append("</section>")

    return "\n".join(html_parts)


def _render_sqli_section(sqli):
    if not isinstance(sqli, dict):
        return f"<pre>{escape(repr(sqli))}</pre>"

    if sqli.get("status") == "sqlmap_run" or "raw_output" in sqli:
        return _render_sqlmap_section(sqli)

    status = sqli.get("status", "unknown")
    findings = sqli.get("findings", [])
    tested_parameters = sqli.get("tested_parameters", [])

    html_parts = [
        "<section>",
        "<h2>Kiểm tra SQL Injection</h2>",
        f"<p><strong>Trạng thái:</strong> {escape(_render_status(status))}</p>",
        f"<p><strong>Số kết quả:</strong> {len(findings)}</p>",
        f"<p><strong>Tham số đã thử:</strong> {len(tested_parameters)}</p>",
    ]

    if status == "baseline_request_failed":
        html_parts.append(
            f"<p><strong>Lỗi:</strong> {escape(str(sqli.get('error', 'unknown')))}</p>"
        )

    if status == "no_parameters_found":
        html_parts.append(
            "<p>URL mục tiêu không chứa tham số truy vấn, do đó không có payload SQLi nào được gửi.</p>"
        )

    if tested_parameters:
        html_parts.append("<h3>Tham số đã thử</h3>")
        html_parts.append("<table border='1' cellspacing='0' cellpadding='6'>")
        show_target_url = any(item.get("target_url") for item in tested_parameters)
        html_parts.append("<tr>")
        if show_target_url:
            html_parts.append("<th>URL mục tiêu</th>")
        html_parts.append("<th>Tham số</th><th>Số payload đã thử</th><th>Số bằng chứng</th></tr>")
        for item in tested_parameters:
            evidence_count = len(item.get("evidence", []))
            html_parts.append("<tr>")
            if show_target_url:
                html_parts.append(f"<td>{escape(str(item.get('target_url', '')))}</td>")
            html_parts.append(
                f"<td>{escape(str(item.get('parameter', '')))}</td>"
                f"<td>{escape(str(item.get('payloads_tested', 0)))}</td>"
                f"<td>{evidence_count}</td>"
                "</tr>"
            )
        html_parts.append("</table>")

    if findings:
        html_parts.append("<h3>Kết quả</h3>")
        html_parts.append("<ul>")
        for finding in findings:
            parameter = escape(str(finding.get("parameter", "")))
            payload = escape(str(finding.get("payload", "")))
            details = finding.get("details", [])
            detail_text = _render_detail_list(details)
            target_url = finding.get("target_url")
            target_text = f" trên {escape(str(target_url))}" if target_url else ""
            html_parts.append(
                f"<li><strong>{parameter}</strong>{target_text} với payload <code>{payload}</code>"
                + (f": {detail_text}" if detail_text else "")
                + "</li>"
            )
        html_parts.append("</ul>")

    html_parts.append("</section>")
    return "\n".join(html_parts)


def _render_xss_section(xss):
    if not isinstance(xss, dict):
        return f"<pre>{escape(repr(xss))}</pre>"

    status = xss.get("status", "unknown")
    findings = xss.get("findings", [])
    tested_parameters = xss.get("tested_parameters", [])

    html_parts = [
        "<section>",
        "<h2>Kiểm tra XSS</h2>",
        f"<p><strong>Trạng thái:</strong> {escape(_render_status(status))}</p>",
        f"<p><strong>Số kết quả:</strong> {len(findings)}</p>",
        f"<p><strong>Tham số đã thử:</strong> {len(tested_parameters)}</p>",
    ]

    if status == "baseline_request_failed":
        html_parts.append(
            f"<p><strong>Lỗi:</strong> {escape(str(xss.get('error', 'unknown')))}</p>"
        )

    if status == "no_parameters_found":
        html_parts.append(
            "<p>URL mục tiêu không chứa tham số truy vấn, do đó không có payload XSS nào được gửi.</p>"
        )

    if tested_parameters:
        html_parts.append("<h3>Tham số đã thử</h3>")
        html_parts.append("<table border='1' cellspacing='0' cellpadding='6'>")
        show_target_url = any(item.get("target_url") for item in tested_parameters)
        html_parts.append("<tr>")
        if show_target_url:
            html_parts.append("<th>URL mục tiêu</th>")
        html_parts.append("<th>Tham số</th><th>Số payload đã thử</th><th>Số bằng chứng</th></tr>")
        for item in tested_parameters:
            evidence_count = len(item.get("evidence", []))
            html_parts.append("<tr>")
            if show_target_url:
                html_parts.append(f"<td>{escape(str(item.get('target_url', '')))}</td>")
            html_parts.append(
                f"<td>{escape(str(item.get('parameter', '')))}</td>"
                f"<td>{escape(str(item.get('payloads_tested', 0)))}</td>"
                f"<td>{evidence_count}</td>"
                "</tr>"
            )
        html_parts.append("</table>")

    if findings:
        html_parts.append("<h3>Kết quả</h3>")
        html_parts.append("<ul>")
        for finding in findings:
            parameter = escape(str(finding.get("parameter", "")))
            payload = escape(str(finding.get("payload", "")))
            details = finding.get("details", [])
            detail_text = _render_detail_list(details)
            target_url = finding.get("target_url")
            target_text = f" trên {escape(str(target_url))}" if target_url else ""
            html_parts.append(
                f"<li><strong>{parameter}</strong>{target_text} với payload <code>{payload}</code>"
                + (f": {detail_text}" if detail_text else "")
                + "</li>"
            )
        html_parts.append("</ul>")

    html_parts.append("</section>")
    return "\n".join(html_parts)


def generate_report(target, report):

    os.makedirs(
        "reports",
        exist_ok=True
    )

    filename = (
        f"reports/report_"
        f"{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    )

    html = f"""
    <html>
    <head>
        <title>Báo Cáo Quét Bảo Mật</title>
        <style>
            body {{ font-family: Arial, sans-serif; line-height: 1.5; max-width: 1100px; margin: 32px auto; padding: 0 16px; }}
            h1, h2, h3 {{ color: #1f2937; }}
            pre {{ background: #f3f4f6; padding: 12px; border-radius: 8px; overflow-x: auto; }}
            table {{ border-collapse: collapse; width: 100%; margin-top: 12px; }}
            th {{ background: #e5e7eb; text-align: left; }}
            th, td {{ border: 1px solid #d1d5db; padding: 8px; vertical-align: top; }}
            section {{ margin-bottom: 28px; }}
            code {{ background: #f3f4f6; padding: 2px 6px; border-radius: 4px; }}
        </style>
    </head>
    <body>

    <h1>Báo Cáo Quét Bảo Mật</h1>

    <h2>Mục Tiêu</h2>
    <pre>{escape(target)}</pre>

    <h2>Headers</h2>
    {_render_pretty_block(report.get('headers', {}))}

    <h2>SSL</h2>
    {_render_pretty_block(report.get('ssl', {}))}

    <h2>Nmap</h2>
    {_render_pretty_block(report.get('nmap', {}))}

    {_render_directory_section(report.get('directory', {}))}

    {_render_target_discovery_section(report.get('target_discovery', {}))}

    {_render_sqli_section(report.get('sqli', {}))}

    {_render_xss_section(report.get('xss', {}))}

    </body>
    </html>
    """

    with open(
        filename,
        "w",
        encoding="utf-8"
    ) as report_file:

        report_file.write(html)

    import json
    json_filename = filename.replace(".html", ".json")
    with open(json_filename, "w", encoding="utf-8") as json_file:
        json.dump(report, json_file, indent=4, ensure_ascii=False)

    print("Saved:", filename)
    return filename, json_filename
