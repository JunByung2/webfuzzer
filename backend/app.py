from flask import Flask, request, jsonify
from flask_cors import CORS
from main import crawl
from datetime import datetime
import threading
import requests as req_lib

from scanner.orchestrator import Orchestrator
from scanner.vuln_analyzer import analyze_vulnerabilities
from scanner.vuln_info_api import vuln_info_bp
from db.payload_repository import update_payload_stats
from db.connection import get_connection
from config.config import (
    DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, DB_NAME,
    GROQ_API_KEY, GROQ_MODEL, GROQ_API_URL,
)

app = Flask(__name__)
CORS(app)

app.register_blueprint(vuln_info_bp)

scan_status = {}


# ══════════════════════════════════════════════════════════════════
# 진행률 계산
# ══════════════════════════════════════════════════════════════════

def calculate_hybrid_progress(target_url, phase, internal_p):
    weights = {"crawling": 30, "scanning": 40, "ai_analysis": 30}
    offsets = {"crawling": 0,  "scanning": 30, "ai_analysis": 70}

    total_progress = offsets[phase] + (internal_p * weights[phase] / 100)

    if target_url in scan_status:
        scan_status[target_url]["progress"] = round(total_progress, 1)
        scan_status[target_url]["phase"]    = phase
        scan_status[target_url]["message"]  = f"{phase} 단계 수행 중... ({internal_p:.0f}%)"


# ══════════════════════════════════════════════════════════════════
# 백그라운드 스캔
# ══════════════════════════════════════════════════════════════════

def background_scan(target_url):
    db_conn = None
    try:
        start_time = datetime.now()
        scan_status[target_url]["start_time"] = start_time.isoformat()

        # 1단계: 크롤링 (0 ~ 30%)
        def crawl_callback(p):
            calculate_hybrid_progress(target_url, "crawling", p)

        pages_result = crawl(target_url, progress_callback=crawl_callback) or []

        # 2단계: 스캔 (30 ~ 70%)
        db_conn      = get_connection()
        orchestrator = Orchestrator(db_connection=db_conn)

        calculate_hybrid_progress(target_url, "scanning", 0)

        full_crawler_json = {
            "results": pages_result,
            "url"    : target_url,
        }
        vuln_results = orchestrator.run(full_crawler_json) or []

        calculate_hybrid_progress(target_url, "scanning", 100)

        # 3단계: AI 분석 (70 ~ 100%)
        scan_status[target_url].update({
            "progress": 85,
            "phase"   : "ai_analysis",
            "message" : "AI 분석 중...",
        })

        vuln_dicts = [
            v.to_dict() if hasattr(v, "to_dict") else v
            for v in vuln_results
        ]

        if vuln_dicts:
            ai_report = analyze_vulnerabilities(vuln_dicts, target_url=target_url)
        else:
            ai_report = {
                "summary": {
                    "target_url": target_url,
                    "scan_date" : datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "total": 0, "critical": 0, "high": 0,
                    "medium": 0, "low": 0, "safe": 0,
                },
                "vulnerabilities": [],
            }

        ai_vuln_count = len(ai_report.get("vulnerabilities", []))
        update_payload_stats(vuln_results)

        print(f"[DEBUG] ai_report 취약점 수: {ai_vuln_count}")
        for v in ai_report.get("vulnerabilities", []):
            print(f"[DEBUG] id={v.get('id')} type={v.get('vuln_type')} ai_description={str(v.get('ai_description',''))!r}")

        scan_status[target_url].update({
            "progress": 95,
            "message" : f"AI 분석 완료 → {ai_vuln_count}개",
        })

        end_time = datetime.now()
        scan_status[target_url].update({
            "status"       : "success",
            "progress"     : 100,
            "phase"        : "done",
            "message"      : "스캔 완료",
            "end_time"     : end_time.isoformat(),
            "duration"     : (end_time - start_time).total_seconds(),
            "page_count"   : len(pages_result),
            "url"          : target_url,
            "results"      : pages_result,
            "crawl_results": pages_result,
            "vuln_count"   : len(vuln_dicts),
            "vuln_results" : vuln_dicts,
            "ai_analysis"  : ai_report,
        })

        # DB 저장
        try:
            req_lib.post(
                "http://127.0.0.1:5000/api/results",
                json={**scan_status[target_url], "target_url": target_url},
                timeout=10,
            )
        except Exception as e:
            print("DB 전송 실패:", e)

    except Exception as e:
        import traceback
        print(f"[SCAN ERROR] {e}")
        traceback.print_exc()
        scan_status[target_url].update({
            "status"  : "error",
            "progress": 100,
            "phase"   : "error",
            "message" : str(e),
        })

    finally:
        if db_conn:
            try:
                db_conn.close()
            except Exception:
                pass


# ══════════════════════════════════════════════════════════════════
# 라우트
# ══════════════════════════════════════════════════════════════════

@app.route("/scan", methods=["POST"])
def start_scan():
    data      = request.json or {}
    start_url = data.get("url", "").strip()

    if not start_url:
        return jsonify({"error": "URL이 필요합니다."}), 400
    if not start_url.startswith("http"):
        start_url = "https://" + start_url

    if scan_status.get(start_url, {}).get("status") == "running":
        print(f"[SCAN] 중복 요청 차단: {start_url}")
        return jsonify({"message": "이미 스캔 중입니다.", "url": start_url}), 409

    scan_status[start_url] = {
        "status"      : "running",
        "progress"    : 0,
        "phase"       : "starting",
        "message"     : "스캔 준비 중...",
        "url"         : start_url,
        "results"     : [],
        "vuln_results": [],
        "ai_analysis" : None,
    }

    thread = threading.Thread(target=background_scan, args=(start_url,))
    thread.daemon = True
    thread.start()

    return jsonify({"message": "스캔이 시작되었습니다.", "url": start_url}), 202


@app.route("/scan/status", methods=["GET"])
def get_status():
    url = request.args.get("url", "").strip()
    if not url or url not in scan_status:
        return jsonify({"status": "not_found"}), 404
    return jsonify(scan_status[url])


@app.route("/api/results", methods=["POST"])
def save_results():
    data      = request.json
    vuln_list = data.get("vuln_results") or []
    print(f"--- DB 저장 시도 시작 --- 취약점 {len(vuln_list)}개")

    try:
        conn = get_connection()
        with conn.cursor() as cursor:
            cursor.execute("""
                INSERT INTO scans (target_url, status, scan_type, progress, page_count, duration, start_time, end_time, created_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, NOW())
            """, (
                data.get("target_url", "unknown"),
                "COMPLETED", "FULL", 100,
                data.get("page_count"),
                data.get("duration"),
                datetime.fromisoformat(data["start_time"]) if data.get("start_time") else None,
                datetime.fromisoformat(data["end_time"])   if data.get("end_time")   else None,
            ))
            scan_id = cursor.lastrowid
            print(f"새로운 스캔 ID 생성됨: {scan_id}")

            for vuln in vuln_list:
                cursor.execute("""
                    INSERT INTO results (scan_id, url, vulnerability, severity, payload, parameter, evidence, source, is_vulnerable, scanned_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (
                    scan_id,
                    vuln.get("url", "N/A"),
                    vuln.get("vuln_type") or vuln.get("vulnerability"),
                    vuln.get("severity"),
                    vuln.get("payload"),
                    vuln.get("parameter"),
                    vuln.get("evidence"),
                    vuln.get("source"),
                    True,
                    datetime.fromisoformat(vuln["scanned_at"]) if vuln.get("scanned_at") else None,
                ))

        conn.commit()
        conn.close()
        return jsonify({"message": "DB 저장 성공", "scan_id": scan_id}), 201

    except Exception as e:
        print("상세 에러 로그:", str(e))
        return jsonify({"error": str(e)}), 500


@app.route("/dashboard", methods=["GET"])
def dashboard():
    try:
        from db.repository import get_dashboard_metrics
        data = get_dashboard_metrics()
        return jsonify(data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/chat", methods=["POST"])
def chat():
    """
    대응방안 AI 채팅 엔드포인트

    Request body:
    {
        "messages": [{"role": "user"|"assistant", "content": "..."}],
        "context": {
            "vuln_type": "xss"|"sqli",
            "parameter": "searchTerm",
            "url": "http://...",
            "payload": "<svg onload=alert(1)>",
            "severity": "HIGH",
            "action": "대응방안 action 텍스트",
            "reason": "대응방안 reason 텍스트"
        }
    }
    """
    data     = request.json or {}
    messages = data.get("messages", [])
    ctx      = data.get("context", {})

    if not messages:
        return jsonify({"error": "messages가 없습니다."}), 400

    system_prompt = f"""당신은 웹 보안 전문가입니다. 개발자가 실제 취약점을 수정하는 것을 돕고 있습니다.

## 현재 취약점 정보
- 취약점 유형: {ctx.get('vuln_type', '').upper()}
- 심각도: {ctx.get('severity', '')}
- 발견된 URL: {ctx.get('url', '')}
- 취약한 파라미터: {ctx.get('parameter', '')}
- 공격에 사용된 페이로드: {ctx.get('payload', '')}

## 현재 논의 중인 대응방안
- 조치: {ctx.get('action', '')}
- 설명: {ctx.get('reason', '')}

## 응답 규칙
- 반드시 한국어로 답변할 것. 한자·일본어·중국어 절대 금지.
- 위 취약점과 대응방안 컨텍스트를 기반으로 구체적으로 답변할 것.
- 개발자가 실제로 코드를 수정할 수 있도록 실용적인 답변을 줄 것.
- 코드 예시는 Python 또는 JavaScript로, 간결하게 제시할 것.
- 같은 말 반복 금지. 완전한 문장으로 마무리할 것."""

    groq_messages = [{"role": "system", "content": system_prompt}] + messages

    try:
        resp = req_lib.post(
            GROQ_API_URL,
            headers={
                "Authorization": f"Bearer {GROQ_API_KEY}",
                "Content-Type" : "application/json",
            },
            json={
                "model"      : GROQ_MODEL,
                "messages"   : groq_messages,
                "temperature": 0.3,
                "max_tokens" : 1024,
            },
            timeout=30,
        )
        raw = resp.json()

        if "error" in raw:
            return jsonify({"error": raw["error"]}), 500

        reply = raw["choices"][0]["message"]["content"]
        return jsonify({"reply": reply})

    except Exception as e:
        print(f"[Chat] Groq 호출 실패: {e}")
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
