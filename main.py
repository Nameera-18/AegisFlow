"""
main.py
--------
FastAPI backend for the AegisFlow prototype.

Endpoints:
  POST /api/upload         -> upload a .pcap/.pcapng file, get back full analysis JSON
  POST /api/capture/start  -> start a LIVE capture with Scapy (needs admin/root + real NIC)
  GET  /api/capture/status -> poll live capture progress
  POST /api/capture/stop   -> stop early and analyze what was captured so far

Run with:
  uvicorn main:app --reload --port 8000

Then open http://localhost:8000 in a browser (the frontend is served as
static files by this same app, so there's nothing else to run).
"""

import os
import time
import threading
import tempfile
import uuid

from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from pcap_parser import parse_pcap, build_flows
from analyzer import analyze_flows, summarize

app = FastAPI(title="AegisFlow Prototype API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


def run_full_pipeline(pcap_path: str):
    records = parse_pcap(pcap_path)
    flows = build_flows(records)
    scored_flows, alerts = analyze_flows(flows)
    summary = summarize(records, scored_flows, alerts)

    timeline = _build_timeline(records)

    return {
        "summary": summary,
        "flows": scored_flows,
        "alerts": alerts,
        "timeline": timeline,
    }


def _build_timeline(records, bucket_seconds: float = 1.0):
    """Bucket packet counts per second so the frontend can draw a
    packets-over-time chart."""
    if not records:
        return []
    t0 = records[0]["time"]
    buckets = {}
    for r in records:
        bucket = int((r["time"] - t0) // bucket_seconds)
        buckets[bucket] = buckets.get(bucket, 0) + 1
    return [{"second": b, "packet_count": c} for b, c in sorted(buckets.items())]


@app.post("/api/upload")
async def upload_pcap(file: UploadFile = File(...)):
    if not file.filename.lower().endswith((".pcap", ".pcapng", ".cap")):
        raise HTTPException(400, "Please upload a .pcap, .pcapng or .cap file")

    suffix = os.path.splitext(file.filename)[1]
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        tmp.write(await file.read())
        tmp_path = tmp.name

    try:
        result = run_full_pipeline(tmp_path)
    except Exception as e:
        raise HTTPException(500, f"Failed to parse capture: {e}")
    finally:
        os.remove(tmp_path)

    return result


# ---------------------------------------------------------------------------
# Live capture (optional). Sniffing real traffic requires the machine you run
# this on to have Npcap/libpcap and the process to have admin/root rights.
# It will NOT work inside a sandboxed container like this prototype was built
# in -- it's here so you can demo real, live capture on your own laptop.
# ---------------------------------------------------------------------------

class CaptureRequest(BaseModel):
    interface: str = None   # e.g. "eth0", "Wi-Fi" -- None lets Scapy pick a default
    duration_seconds: int = 15


_capture_state = {"running": False, "packets": [], "error": None, "job_id": None}


def _capture_worker(interface, duration_seconds, job_id):
    from scapy.all import sniff, wrpcap

    def on_packet(pkt):
        if _capture_state["job_id"] != job_id:
            return
        _capture_state["packets"].append(pkt)

    try:
        sniff(iface=interface, timeout=duration_seconds, prn=on_packet, store=False)
    except Exception as e:
        _capture_state["error"] = str(e)
    finally:
        if _capture_state["job_id"] == job_id:
            _capture_state["running"] = False


@app.post("/api/capture/start")
def start_capture(req: CaptureRequest):
    if _capture_state["running"]:
        raise HTTPException(409, "A capture is already running")

    job_id = str(uuid.uuid4())
    _capture_state.update(running=True, packets=[], error=None, job_id=job_id)

    thread = threading.Thread(
        target=_capture_worker,
        args=(req.interface, req.duration_seconds, job_id),
        daemon=True,
    )
    thread.start()
    return {"status": "started", "job_id": job_id, "duration_seconds": req.duration_seconds}


@app.get("/api/capture/status")
def capture_status():
    return {
        "running": _capture_state["running"],
        "packets_captured": len(_capture_state["packets"]),
        "error": _capture_state["error"],
    }


@app.post("/api/capture/stop")
def stop_capture():
    if not _capture_state["packets"] and not _capture_state["running"]:
        raise HTTPException(400, "No capture in progress or completed to analyze")

    _capture_state["running"] = False
    _capture_state["job_id"] = None  # tells the worker thread to stop appending

    from scapy.all import wrpcap
    tmp_path = os.path.join(tempfile.gettempdir(), f"aegisflow_{uuid.uuid4()}.pcap")
    wrpcap(tmp_path, _capture_state["packets"])

    try:
        result = run_full_pipeline(tmp_path)
    finally:
        os.remove(tmp_path)

    return result


# Serve the frontend (index.html + assets) at "/"
frontend_dir = os.path.join(os.path.dirname(__file__), "..", "frontend")
app.mount("/", StaticFiles(directory=frontend_dir, html=True), name="frontend")
