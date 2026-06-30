"""
api.py
FastAPI app exposing:
  GET  /                 -> dashboard UI
  GET  /api/providers     -> list available LLM providers (for dropdown)
  POST /api/analyze       -> run full pipeline on uploaded log file or pasted text
  GET  /api/report/{file} -> download a generated report
"""
import os
from fastapi import FastAPI, UploadFile, File, Form
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles

from core.pipeline import run_pipeline
from core.llm_analysis import list_available_providers
from core.config import OUTPUT_DIR

app = FastAPI(title="SecAnalyzer - AI Log Analysis & Incident Reporting")


@app.get("/api/providers")
def get_providers():
    return JSONResponse(list_available_providers())


@app.post("/api/analyze")
async def analyze(
    file: UploadFile = File(None),
    log_text: str = Form(None),
    llm_provider: str = Form(None),
    run_llm: bool = Form(True),
):
    if file:
        content = (await file.read()).decode(errors="ignore")
        source_name = file.filename
    elif log_text:
        content = log_text
        source_name = "pasted_text"
    else:
        return JSONResponse({"error": "Provide either a file or log_text"}, status_code=400)

    result = run_pipeline(content, source_name=source_name, llm_provider=llm_provider, run_llm=run_llm)

    return JSONResponse({
        "event_count": len(result["events"]),
        "detections": result["detections"],
        "timeline": result["timeline"],
        "timeline_summary": result["timeline_summary"],
        "overall_risk": result["overall_risk"],
        "llm_result": result["llm_result"],
        "report_markdown": result["report_markdown"],
        "report_files": {
            "markdown": os.path.basename(result["report_paths"]["markdown"]),
            "json": os.path.basename(result["report_paths"]["json"]),
        },
    })


@app.get("/api/report/{filename}")
def get_report(filename: str):
    path = os.path.join(OUTPUT_DIR, filename)
    if not os.path.exists(path):
        return JSONResponse({"error": "not found"}, status_code=404)
    return FileResponse(path)


@app.get("/", response_class=HTMLResponse)
def dashboard():
    dashboard_path = os.path.join(os.path.dirname(__file__), "static", "index.html")
    with open(dashboard_path, encoding="utf-8") as f:
        return f.read()


if os.path.isdir(os.path.join(os.path.dirname(__file__), "static")):
    app.mount("/static", StaticFiles(directory=os.path.join(os.path.dirname(__file__), "static")), name="static")
