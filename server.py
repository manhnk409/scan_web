import asyncio
import threading
import os
import glob
import json
from datetime import datetime
from pydantic import BaseModel
from fastapi import FastAPI, HTTPException
from fastapi.responses import StreamingResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from main import run_scan

app = FastAPI(title="SentinX Scanner API")

# Enable CORS for local development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Store scan tasks
# scan_id -> ScanRunner instance
active_scans = {}

class ScanRequest(BaseModel):
    url: str
    insecure: bool = False

class ScanRunner:
    def __init__(self, target, insecure, loop):
        self.target = target
        self.insecure = insecure
        self.loop = loop
        self.queue = asyncio.Queue()
        self.logs = []
        self.status = "idle"
        self.report_id = None
        self.error = None

    def log_callback(self, message, step=None, status=None):
        payload = {
            "type": "log",
            "message": message,
            "step": step,
            "status": status,
            "timestamp": datetime.now().isoformat()
        }
        self.logs.append(payload)
        # Put into the asyncio queue thread-safely
        self.loop.call_soon_threadsafe(self.queue.put_nowait, payload)

    def run(self):
        self.status = "running"
        try:
            # Execute the scanner sequence imported from main.py
            report, html_path, json_path = run_scan(
                self.target,
                insecure=self.insecure,
                log_callback=self.log_callback
            )
            self.report_id = os.path.basename(json_path).replace(".json", "")
            self.status = "completed"
            
            # Send completion message
            self.loop.call_soon_threadsafe(
                self.queue.put_nowait, 
                {"type": "done", "report_id": self.report_id}
            )
        except Exception as e:
            self.status = "failed"
            self.error = str(e)
            self.log_callback(f"Scan failed: {str(e)}", step="report", status="failed")
            self.loop.call_soon_threadsafe(
                self.queue.put_nowait, 
                {"type": "error", "error": str(e)}
            )

@app.post("/api/scan")
async def start_scan(req: ScanRequest):
    target = req.url.strip()
    if not target:
        raise HTTPException(status_code=420, detail="URL cannot be empty")
        
    if not target.startswith(("http://", "https://")):
        target = "http://" + target

    # Generate a temporary scan id for live tracking
    scan_id = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    loop = asyncio.get_running_loop()
    runner = ScanRunner(target, req.insecure, loop)
    active_scans[scan_id] = runner

    # Start the scanning thread
    thread = threading.Thread(target=runner.run, daemon=True)
    thread.start()

    return {"scan_id": scan_id}

@app.get("/api/scan/progress/{scan_id}")
async def get_progress(scan_id: str):
    if scan_id not in active_scans:
        raise HTTPException(status_code=404, detail="Scan job not found")

    runner = active_scans[scan_id]

    async def event_generator():
        # Yield already generated logs immediately
        for log in runner.logs:
            yield f"data: {json.dumps(log)}\n\n"

        if runner.status == "completed":
            yield f"data: {json.dumps({'type': 'done', 'report_id': runner.report_id})}\n\n"
            return
        elif runner.status == "failed":
            yield f"data: {json.dumps({'type': 'error', 'error': runner.error})}\n\n"
            return

        # Poll the queue for ongoing status events
        while True:
            try:
                item = await runner.queue.get()
                yield f"data: {json.dumps(item)}\n\n"
                if item.get("type") in ("done", "error"):
                    break
            except asyncio.CancelledError:
                break

    return StreamingResponse(event_generator(), media_type="text/event-stream")

@app.get("/api/reports")
async def list_reports():
    report_files = glob.glob("reports/report_*.json")
    reports_list = []
    
    for f in report_files:
        try:
            report_id = os.path.basename(f).replace(".json", "")
            stat = os.stat(f)
            created_at = datetime.fromtimestamp(stat.st_mtime).isoformat()
            
            with open(f, "r", encoding="utf-8") as file:
                data = json.load(file)
            
            # Resolve target URL
            target = data.get("target_url", data.get("target", "unknown"))
            if not target or target == "auto-discovered targets":
                target = data.get("directory", {}).get("target_url", "unknown")

            # Extract quick metrics for list summary cards
            stats = {
                "headers_missing": sum(1 for h, val in data.get("headers", {}).items() if not val) if isinstance(data.get("headers"), dict) else 0,
                "ssl_verified": data.get("ssl", {}).get("verification") == "enabled",
                "open_ports": len(data.get("nmap", {}).get("tcp", [])) if isinstance(data.get("nmap"), dict) and "tcp" in data.get("nmap", {}) else 0,
                "sqli_vulnerable": data.get("sqli", {}).get("status") in ("potential_vulnerability_detected", "sqlmap_run"),
                "xss_vulnerable": data.get("xss", {}).get("status") in ("input_reflection_observed"),
                "sqli_count": len(data.get("sqli", {}).get("confirmed_findings", [])) + len(data.get("sqli", {}).get("findings", [])),
                "xss_count": len(data.get("xss", {}).get("findings", []))
            }
            
            reports_list.append({
                "id": report_id,
                "target": target,
                "created_at": created_at,
                "stats": stats
            })
        except Exception:
            continue
            
    reports_list.sort(key=lambda x: x["created_at"], reverse=True)
    return reports_list

@app.get("/api/reports/{report_id}")
async def get_report_details(report_id: str):
    json_path = f"reports/{report_id}.json"
    if not os.path.exists(json_path):
        raise HTTPException(status_code=404, detail="JSON report file not found")
    
    try:
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read report: {str(e)}")

@app.get("/api/reports/{report_id}/html")
async def get_report_html(report_id: str):
    html_path = f"reports/{report_id}.html"
    if not os.path.exists(html_path):
        raise HTTPException(status_code=404, detail="HTML report file not found")
    return FileResponse(html_path, media_type="text/html", filename=f"{report_id}.html")

@app.delete("/api/reports/{report_id}")
async def delete_report(report_id: str):
    json_path = f"reports/{report_id}.json"
    html_path = f"reports/{report_id}.html"
    
    deleted = False
    if os.path.exists(json_path):
        os.remove(json_path)
        deleted = True
    if os.path.exists(html_path):
        os.remove(html_path)
        deleted = True
        
    if not deleted:
        raise HTTPException(status_code=404, detail="Report not found")
    return {"status": "success"}

# Serve frontend static files
os.makedirs("static", exist_ok=True)
app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/")
async def read_index():
    return FileResponse("static/index.html")
