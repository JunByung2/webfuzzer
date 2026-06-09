"""
scanner/payload_recommender.py
"""

import json
import time
import requests

from config.config import GROQ_API_KEY, GROQ_MODEL, GROQ_API_URL


def get_payload_history(db_connection, vuln_type: str) -> list:
    cursor = db_connection.cursor()
    cursor.execute("""
        SELECT
            payload,
            vulnerability,
            MIN(url) as url,
            parameter,
            MIN(evidence) as evidence,
            MAX(scanned_at) as last_seen,
            COUNT(*) as success_count,
            COUNT(DISTINCT url) as affected_urls
        FROM results
        WHERE vulnerability = %s AND is_vulnerable = 1 AND payload IS NOT NULL
        GROUP BY payload, vulnerability, parameter
        ORDER BY success_count DESC, affected_urls DESC
        LIMIT 20
    """, (vuln_type,))

    rows = cursor.fetchall()

    result = []
    for row in rows:
        if isinstance(row, dict):
            result.append({
                "payload"      : row["payload"],
                "vuln_type"    : row["vulnerability"],
                "url"          : row["url"],
                "parameter"    : row["parameter"],
                "evidence"     : row["evidence"],
                "last_seen"    : str(row["last_seen"]),
                "success_count": row["success_count"],
                "affected_urls": row["affected_urls"],
            })
        else:
            result.append({
                "payload"      : row[0],
                "vuln_type"    : row[1],
                "url"          : row[2],
                "parameter"    : row[3],
                "evidence"     : row[4],
                "last_seen"    : str(row[5]),
                "success_count": row[6],
                "affected_urls": row[7],
            })
    return result


def build_recommend_prompt(vuln_type: str, history: list, target_url: str) -> list:
    history_text = "\n".join([
        f"- [{i+1}] payload: {h['payload']} | 탐지횟수: {h['success_count']}회 | 영향받은URL: {h['affected_urls']}개 | 파라미터: {h['parameter']} | 마지막탐지: {h['last_seen']}"
        for i, h in enumerate(history)
    ]) if history else "이력 없음 (첫 스캔)"

    system_prompt = """
당신은 웹 보안 페이로드 전문가입니다.
과거 스캔 이력을 분석하여 다음 스캔에서 시도할 페이로드 순서를 추천하세요.

추천 기준 (투명하게 명시):
1. success_rate(공격 성공률)가 높은 페이로드 우선
2. hit_count(시도 횟수)가 적은 페이로드는 success_rate가 높아도 신뢰도가 낮으므로 우선순위 하향
3. confidence_score(탐지 신뢰도)가 낮은 페이로드는 오탐 가능성이 높으므로 우선순위 하향
4. last_success_at(마지막 성공 시각)이 최근일수록 우선
5. context_stats에서 현재 파라미터명, 파라미터 타입, HTTP 메서드 조건과 일치하는 세부 성공률이 있을 경우 글로벌 success_rate보다 우선 적용
6. response_time_avg(평균 응답 시간)가 긴 페이로드는 Blind SQLi 탐지 상황에서 우선 추천
7. source_cve 값이 있는 페이로드는 검증된 공격 패턴으로 간주하여 신뢰도 가산

반드시 아래 JSON 형식으로만 반환하세요. 다른 텍스트는 절대 출력하지 마세요.

{
  "recommended_order": [
    {
      "rank": 1,
      "payload": "페이로드 문자열",
      "score": 85,
      "basis": "탐지횟수 3회, 영향URL 2개 기반"
    }
  ],
  "strategy": "전체 추천 전략 한 줄 요약"
}
"""

    user_message = f"""
대상 URL: {target_url}
취약점 유형: {vuln_type.upper()}

[과거 성공 페이로드 이력]
{history_text}

위 이력을 바탕으로 다음 스캔에서 시도할 페이로드 순서를 추천해주세요.
이력이 없으면 일반적으로 효과적인 기본 순서를 추천하세요.
"""

    return [
        {"role": "system", "content": system_prompt},
        {"role": "user",   "content": user_message},
    ]


def call_groq_with_retry(messages: list, max_retries: int = 3, retry_delay: float = 2.0) -> str:
    """Groq API 호출 — 빈 응답이나 rate limit 시 재시도"""
    for attempt in range(1, max_retries + 1):
        try:
            response = requests.post(
                GROQ_API_URL,
                headers={
                    "Authorization": f"Bearer {GROQ_API_KEY}",
                    "Content-Type" : "application/json",
                },
                json={
                    "model"      : GROQ_MODEL,
                    "messages"   : messages,
                    "temperature": 0.1,
                },
                timeout=30,
            )
            raw_json = response.json()

            if "error" in raw_json:
                err = raw_json["error"]
                print(f"[PayloadAI] Groq 에러 (시도 {attempt}/{max_retries}): {err}")
                if attempt < max_retries:
                    time.sleep(retry_delay * attempt)
                continue

            raw = raw_json.get("choices", [{}])[0].get("message", {}).get("content", "")

            if not raw.strip():
                print(f"[PayloadAI] 빈 응답 수신 (시도 {attempt}/{max_retries}), {retry_delay * attempt}초 후 재시도...")
                if attempt < max_retries:
                    time.sleep(retry_delay * attempt)
                continue

            return raw

        except Exception as e:
            print(f"[PayloadAI] 요청 실패 (시도 {attempt}/{max_retries}): {e}")
            if attempt < max_retries:
                time.sleep(retry_delay * attempt)

    return ""


def recommend_payload_order(db_connection, vuln_type: str, target_url: str) -> dict:
    history = get_payload_history(db_connection, vuln_type)
    print(f"\n[PayloadAI] ── 추천 시작 ──────────────────────────────")
    print(f"[PayloadAI] vuln_type   : {vuln_type.upper()}")
    print(f"[PayloadAI] target_url  : {target_url}")
    print(f"[PayloadAI] DB 이력     : {len(history)}개 로드")

    messages = build_recommend_prompt(vuln_type, history, target_url)
    raw      = call_groq_with_retry(messages)

    print(f"[PayloadAI] LLM 원본 응답 ↓\n{raw}\n")

    result = parse_response(raw)
    result["vuln_type"]     = vuln_type
    result["history_count"] = len(history)

    print(f"[PayloadAI] 파싱된 반환값 ↓")
    print(json.dumps(result, ensure_ascii=False, indent=2))

    recommended = result.get("recommended_order", [])
    print(f"\n[PayloadAI] 추천 페이로드 순서 ({len(recommended)}개)")
    for item in recommended:
        print(f"  #{item.get('rank','?')} score={item.get('score','?'):>3} | {item.get('payload','')[:60]}")
        print(f"       근거: {item.get('basis','')}")
    print(f"[PayloadAI] 전략: {result.get('strategy', 'N/A')}")
    print(f"[PayloadAI] ────────────────────────────────────────────\n")

    return result


def parse_response(raw: str) -> dict:
    import re

    def extract_json(text):
        match = re.search(r'```(?:json)?\s*(.*?)\s*```', text, re.DOTALL)
        if match:
            return match.group(1).strip()
        match = re.search(r'\{.*\}', text, re.DOTALL)
        if match:
            return match.group().strip()
        return text.strip()

    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        pass

    extracted = extract_json(raw)
    try:
        return json.loads(extracted)
    except json.JSONDecodeError:
        pass

    try:
        import re as _re
        fixed = _re.sub(r"(?<=['\w])'(?=['\w])", "\\'", extracted)
        return json.loads(fixed)
    except Exception:
        pass

    return {"raw_response": raw, "parse_error": True}


if __name__ == "__main__":
    import pymysql
    from config.config import DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, DB_NAME

    db_connection = pymysql.connect(
        host     = DB_HOST,
        port     = DB_PORT,
        user     = DB_USER,
        password = DB_PASSWORD,
        database = DB_NAME,
    )

    result = recommend_payload_order(db_connection, vuln_type="xss", target_url="https://example.com")
    db_connection.close()