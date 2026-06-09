"""
scanner/vuln_info_api.py
"""

import json
import os
from flask import Blueprint, jsonify, request
from backend.scanner.vuln_analyzer import analyze_vulnerabilities

vuln_info_bp = Blueprint("vuln_info", __name__)

_JSON_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vuln_info.json")
_cache = None


def _load() -> dict:
    global _cache
    if _cache is None:
        with open(_JSON_PATH, "r", encoding="utf-8") as f:
            _cache = json.load(f)
    return _cache


@vuln_info_bp.route("/vuln-info/by-result", methods=["POST"])
def get_vuln_info_by_result():
    body      = request.json or {}
    vuln_type = body.get("vuln_type", "").lower().strip()

    if vuln_type in ("sql", "sqli", "sql_injection"):
        vuln_type = "sqli"
    elif vuln_type in ("xss", "cross_site_scripting"):
        vuln_type = "xss"

    data = _load()
    if vuln_type not in data:
        return jsonify({
            "error"    : f"지원하지 않는 취약점 유형: {vuln_type}",
            "supported": list(data.keys())
        }), 404

    info = data[vuln_type]

    ai_report = analyze_vulnerabilities([body], target_url=body.get("url", ""))
    ai_vuln   = ai_report.get("vulnerabilities", [{}])[0]

    # AI가 생성한 맞춤 대응방안 우선, 없으면 vuln_info.json 정적 fallback
    ai_remediation = ai_vuln.get("ai_remediation", [])
    remediation    = ai_remediation if ai_remediation else info["remediation"]

    result = {
        # 스캔 원본 정보
        "vuln_type"     : vuln_type,
        "url"           : body.get("url", ""),
        "parameter"     : body.get("parameter", ""),
        "payload"       : body.get("payload", ""),
        "source"        : body.get("source", ""),
        "reflection"    : body.get("reflection", ""),
        # AI 분석 결과
        "severity"      : ai_vuln.get("severity", body.get("severity", "MEDIUM")),
        "cvss"          : ai_vuln.get("cvss", 5.0),
        "evidence"      : ai_vuln.get("evidence", body.get("evidence", "")),
        "ai_description": ai_vuln.get("ai_description", ""),
        # JSON 고정 정보
        "name"          : info["name"],
        "description"   : info["description"],
        "impact"        : info["impact"],
        # AI 맞춤 대응방안 (없으면 정적 fallback)
        "remediation"   : remediation,
    }

    return jsonify(result)


@vuln_info_bp.route("/vuln-info/<vuln_type>", methods=["GET"])
def get_vuln_info(vuln_type: str):
    data = _load()
    key  = vuln_type.lower().strip()
    if key in ("sql", "sqli"):
        key = "sqli"
    elif key == "xss":
        key = "xss"

    if key not in data:
        return jsonify({
            "error"    : f"지원하지 않는 취약점 유형: {vuln_type}",
            "supported": list(data.keys())
        }), 404

    return jsonify(data[key])