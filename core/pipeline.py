"""
pipeline.py
Orchestrates the full pipeline:
Logs -> Parser -> Normalizer -> Detection Engine -> Threat Intel -> MITRE Mapper
-> Timeline Builder -> Risk Scoring -> LLM Analysis -> Incident Report
"""
from core import parser, normalizer, detection_engine, threat_intel, mitre_mapper
from core import timeline_builder, risk_scoring, llm_analysis, report_generator


def run_pipeline(log_text: str, source_name="uploaded_log", llm_provider=None, run_llm=True):
    # 1. Parse
    parsed = parser.parse_log_text(log_text)

    # 2. Normalize
    events = normalizer.normalize_records(parsed)

    # 3. Detection Engine
    raw_detections = detection_engine.run_detections(events)

    # 4. Threat Intelligence enrichment
    enriched_detections = threat_intel.enrich_detections(raw_detections)

    # 5. MITRE Mapping
    mapped_detections = mitre_mapper.map_detections(enriched_detections)

    # 6. Risk Scoring
    scored_detections = risk_scoring.score_all(mapped_detections)
    overall_risk = risk_scoring.overall_incident_score(scored_detections)

    # 7. Timeline
    timeline = timeline_builder.build_timeline(events, scored_detections)
    tl_summary = timeline_builder.timeline_summary(timeline)

    # 8. LLM Analysis (optional / pluggable)
    llm_result = {}
    if run_llm and scored_detections:
        llm_result = llm_analysis.run_llm_analysis(scored_detections, timeline, overall_risk, llm_provider)
    elif not scored_detections:
        llm_result = {"provider": llm_provider, "analysis": "No detections found — nothing to analyze."}

    # 9. Report
    json_payload = {
        "source_name": source_name,
        "event_count": len(events),
        "detections": scored_detections,
        "timeline": timeline,
        "timeline_summary": tl_summary,
        "overall_risk": overall_risk,
        "llm_result": llm_result,
    }
    report_text = report_generator.generate_markdown_report(
        events, scored_detections, timeline, overall_risk, llm_result,
        meta={"source_name": source_name},
    )
    md_path, json_path = report_generator.save_report(report_text, json_payload)

    return {
        "events": events,
        "detections": scored_detections,
        "timeline": timeline,
        "timeline_summary": tl_summary,
        "overall_risk": overall_risk,
        "llm_result": llm_result,
        "report_markdown": report_text,
        "report_paths": {"markdown": md_path, "json": json_path},
    }
