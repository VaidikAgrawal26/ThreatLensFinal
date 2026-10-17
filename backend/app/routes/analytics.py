import csv
import io
from collections import Counter
from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from fastapi.responses import StreamingResponse
from sqlalchemy import desc, func
from sqlalchemy.orm import Session

from app.core.security import get_current_user
from app.db import get_db
from app.models import Scan

router = APIRouter(
    prefix="/api/analytics", tags=["Analytics"], dependencies=[Depends(get_current_user)],
)
REPORT_SCAN_LIMIT = 5000
REPORT_HIGHLIGHT_LIMIT = 100


def rows(db: Session) -> list[Scan]:
    return db.query(Scan).order_by(desc(Scan.id)).limit(REPORT_SCAN_LIMIT).all()


def scan_summary(scan: Scan) -> dict:
    evidence = scan.result_json or {}
    features = evidence.get("features") or {}
    yara_data = evidence.get("yara") or {}
    matches = evidence.get("yara_matches") or (yara_data.get("matches", []) if isinstance(yara_data, dict) else [])
    prediction = evidence.get("ml_prediction") or {}
    indicators = evidence.get("indicators") or {}
    return {
        "id": scan.id,
        "filename": scan.filename,
        "sha256": scan.sha256,
        "md5": scan.md5,
        "file_size": scan.file_size,
        "file_type": scan.file_type,
        "verdict": scan.verdict,
        "severity": scan.severity,
        "risk_score": scan.risk_score,
        "risk_components": evidence.get("risk_components") or evidence.get("risk_breakdown") or {},
        "risk_reasons": evidence.get("reasons") or evidence.get("assessment_reasons") or [],
        "yara_count": scan.yara_count or len(matches),
        "yara_matches": matches,
        "ml": {
            "available": prediction.get("available", bool(scan.ml_label)),
            "label": scan.ml_label or prediction.get("label"),
            "score": scan.ml_score if scan.ml_score is not None else prediction.get("score"),
            "note": prediction.get("note") or prediction.get("reason"),
        },
        "indicators": indicators,
        "measured_features": features,
        "created_at": scan.created_at.isoformat() if scan.created_at else None,
    }


@router.get("/overview")
def overview(db: Session = Depends(get_db)):
    data = rows(db)
    total = db.query(func.count(Scan.id)).scalar() or 0
    severity = {key: sum(x.severity == key for x in data) for key in ["low", "medium", "high", "critical"]}
    verdict: Counter = Counter(x.verdict or "unknown" for x in data)
    daily: Counter = Counter(x.created_at.isoformat()[:10] if x.created_at else "unknown" for x in data)
    return {
        "total_scans": total,
        "records_analyzed": len(data),
        "malicious_suspected": sum(x.verdict == "malicious_suspected" for x in data),
        "suspicious": sum(x.verdict == "suspicious" for x in data),
        "high_risk": sum(x.severity in {"high", "critical"} for x in data),
        "average_risk_score": round(sum(x.risk_score or 0 for x in data) / len(data), 2) if data else 0,
        "severity_distribution": severity,
        "verdict_distribution": dict(verdict),
        "daily_trend": [{"date": key, "scans": value} for key, value in sorted(daily.items())[-14:]],
        "recent_scans": [scan_summary(x) for x in data[:10]],
    }


@router.get("/notifications")
def notifications(db: Session = Depends(get_db)):
    items = []
    for scan in rows(db):
        if scan.severity in {"high", "critical"} or scan.yara_count or scan.verdict == "malicious_suspected":
            items.append({
                "id": scan.id, "title": f"Threat scan: {scan.filename}", "severity": scan.severity,
                "verdict": scan.verdict, "risk_score": scan.risk_score, "yara_count": scan.yara_count,
                "created_at": scan.created_at,
            })
    return {"count": len(items), "items": items[:50]}


@router.get("/security-report")
def report(db: Session = Depends(get_db)):
    data = rows(db)
    total = db.query(func.count(Scan.id)).scalar() or 0
    severe = [x for x in data if x.severity in {"high", "critical"} or (x.risk_score or 0) >= 60]
    severity = Counter((x.severity or "unknown").lower() for x in data)
    verdicts = Counter(x.verdict or "unknown" for x in data)
    types = Counter(x.file_type or "unknown" for x in data)
    daily = Counter(x.created_at.isoformat()[:10] if x.created_at else "unknown" for x in data)
    unique_hashes = len({x.sha256 for x in data if x.sha256})
    yara_scans = sum((x.yara_count or 0) > 0 for x in data)
    ml_available = sum(bool(x.ml_label) or bool(((x.result_json or {}).get("ml_prediction") or {}).get("available")) for x in data)
    pe_scans = sum(bool((x.result_json or {}).get("features", {}).get("is_pe")) for x in data)
    risk_values = [float(x.risk_score or 0) for x in data]
    ordered_risks = sorted(risk_values)
    middle = len(ordered_risks) // 2
    median_risk = (ordered_risks[middle] if len(ordered_risks) % 2 else (ordered_risks[middle - 1] + ordered_risks[middle]) / 2) if ordered_risks else 0
    analysis_window = data

    return {
        "report_title": "ThreatLens AI · Detailed Static Triage Analysis",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scope": {
            "mode": "static file triage",
            "total_records_in_database": total,
            "records_analyzed": len(analysis_window),
            "records_included_in_findings": min(len(severe), REPORT_HIGHLIGHT_LIMIT),
            "analysis_window": f"Most recent {REPORT_SCAN_LIMIT} stored scan records, ordered by scan ID",
            "unique_sha256_in_window": unique_hashes,
        },
        "summary": {
            "malicious_suspected": sum(x.verdict == "malicious_suspected" for x in data),
            "suspicious": sum(x.verdict == "suspicious" for x in data),
            "high_or_critical": sum(x.severity in {"high", "critical"} for x in data),
            "risk_threshold_candidates": sum((x.risk_score or 0) >= 60 for x in data),
            "mean_heuristic_risk": round(sum(risk_values) / len(risk_values), 2) if risk_values else 0,
            "median_heuristic_risk": round(median_risk, 2),
        },
        "evidence_coverage": {
            "scans_with_yara_matches": yara_scans,
            "scans_with_ml_output": ml_available,
            "scans_with_pe_features": pe_scans,
            "scans_without_ml_output": max(0, len(data) - ml_available),
        },
        "distributions": {
            "severity": dict(severity),
            "verdict": dict(verdicts),
            "file_type": dict(types.most_common(25)),
            "daily_scan_volume": [{"date": key, "scans": value} for key, value in sorted(daily.items())[-30:]],
        },
        "priority_findings": [scan_summary(x) for x in sorted(
            severe, key=lambda item: (item.risk_score or 0, item.id), reverse=True,
        )[:REPORT_HIGHLIGHT_LIMIT]],
        "methodology": [
            "Findings summarize stored static-analysis records; files are not executed by this service.",
            "Risk score and verdict are triage signals, not calibrated malware probabilities.",
            "YARA matches depend on the local installed rules and their compilation/evaluation state.",
            "ML output is included only when recorded; missing or unavailable inference is not a benign result.",
            "No accuracy, precision, recall, or family attribution is inferred from unlabeled scan records.",
        ],
        "limitations": [
            "Static analysis cannot observe runtime behavior such as process, registry, or live network activity.",
            "Summary statistics use the most recent 5,000 scans; total_records_in_database reports the full database count.",
            "Priority findings are capped at 100 records and are ranked by heuristic risk score.",
        ],
    }


@router.get("/security-report.csv")
def report_csv(db: Session = Depends(get_db)):
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id", "filename", "sha256", "md5", "file_type", "file_size", "verdict", "severity", "risk_score", "yara_count", "ml_label", "created_at"])
    for scan in rows(db):
        writer.writerow([scan.id, scan.filename, scan.sha256, scan.md5, scan.file_type, scan.file_size,
                         scan.verdict, scan.severity, scan.risk_score, scan.yara_count, scan.ml_label, scan.created_at])
    output.seek(0)
    return StreamingResponse(iter([output.getvalue()]), media_type="text/csv", headers={
        "Content-Disposition": "attachment; filename=threatlens_detailed_scan_report.csv",
    })


@router.get("/export.csv")
def export(db: Session = Depends(get_db)):
    return report_csv(db)
