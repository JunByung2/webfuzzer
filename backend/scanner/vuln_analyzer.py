"""
scanner/vuln_analyzer.py
------------------------
스캔 결과(VulnResult 리스트) → Groq API 분석 → 프론트엔드 보고서용 구조화된 결과 반환

[필드 구조]
  evidence        : 스캐너가 탐지한 원본 근거 (예: "페이로드 반사 확인 (raw)")
  ai_description  : AI가 생성한 "왜 위험한지" 쉬운 설명 (일반인 대상, 실제 페이로드 기반)
  ai_remediation  : AI가 생성한 맞춤 대응방안 (파라미터/URL 직접 언급, 정적 fallback 있음)

[Groq 호출 전략]
  취약점 N개 → Groq 1번 호출 (severity + ai_description + remediation 배열 반환)
  max_tokens=4096으로 응답 잘림 방지
"""

import json
import re
import logging
from typing import Optional
from datetime import datetime
from groq import Groq

from config.config import GROQ_API_KEY, GROQ_MODEL

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger(__name__)

SEVERITY_MAP = {
    "critical": "CRITICAL",
    "high"    : "HIGH",
    "medium"  : "MEDIUM",
    "low"     : "LOW",
    "safe"    : "SAFE",
    "info"    : "LOW",
    "none"    : "SAFE",
}
CVSS_MAP = {
    "CRITICAL": 9.0,
    "HIGH"    : 7.5,
    "MEDIUM"  : 5.0,
    "LOW"     : 2.5,
    "SAFE"    : 0.0,
}


# ══════════════════════════════════════════════════════════════════
# 1. 메인 진입점
# ══════════════════════════════════════════════════════════════════

def analyze_vulnerabilities(vuln_results: list, target_url: str = "") -> dict:
    empty_report = _make_empty_report(target_url)

    if not vuln_results:
        logger.info("[VulnAnalyzer] 분석할 취약점 없음")
        return empty_report

    raw_list = []
    for r in vuln_results:
        if hasattr(r, "to_dict"):
            raw_list.append(r.to_dict())
        elif isinstance(r, dict):
            raw_list.append(r)

    targets = [r for r in raw_list if r.get("severity", "").upper() != "SAFE"]

    if not targets:
        logger.info("[VulnAnalyzer] SAFE만 있음 → 분석 건너뜀")
        return empty_report

    logger.info(f"[VulnAnalyzer] 분석 시작 → {len(targets)}개 취약점 (Groq 1번 호출)")

    cleaned_list = [_preprocess(v) for v in targets]

    ai_results = _analyze_batch(cleaned_list)

    vulnerabilities = []
    for idx, vuln in enumerate(cleaned_list, 1):
        ai = ai_results[idx - 1] if idx - 1 < len(ai_results) else {}

        severity = _map_severity(ai.get("severity", "")) or vuln["severity"]

        result = {
            "id"             : idx,
            "vuln_type"      : vuln["vuln_type"],
            "url"            : vuln["url"],
            "parameter"      : vuln["parameter"],
            "payload"        : vuln["payload"],
            "source"         : vuln["source"],
            "reflection"     : vuln["reflection"],
            "severity"       : severity,
            "cvss"           : CVSS_MAP.get(severity, 5.0),
            "evidence"       : vuln["evidence"],
            "ai_description" : ai.get("ai_description", ""),
            "ai_remediation" : ai.get("remediation", []),
        }
        vulnerabilities.append(result)

    logger.info(f"[VulnAnalyzer] 분석 완료 → {len(vulnerabilities)}개 결과")

    return {
        "summary"        : _make_summary(target_url, vulnerabilities),
        "vulnerabilities": vulnerabilities,
    }


# ══════════════════════════════════════════════════════════════════
# 2. 배치 분석 (Groq 1번 호출)
# ══════════════════════════════════════════════════════════════════

def _analyze_batch(vulns: list) -> list:
    slim = [
        {
            "idx"      : i + 1,
            "type"     : v["vuln_type"].upper(),
            "url"      : v["url"],
            "parameter": v["parameter"],
            "payload"  : v["payload"],
            "evidence" : v["evidence"],
            "source"   : v["source"],
        }
        for i, v in enumerate(vulns)
    ]

    prompt = f"""당신은 웹 보안 전문가입니다. 아래는 실제 웹사이트에서 탐지된 취약점 목록입니다.

{json.dumps(slim, ensure_ascii=False)}

반드시 JSON 배열만 반환. 설명 없이, 마크다운 없이. 정확히 {len(vulns)}개.

각 객체의 작성 규칙:

[ai_description]
언어 규칙:
- 반드시 한국어만 사용할 것. 한자, 일본어, 중국어 문자 사용 절대 금지.
- 같은 표현 반복 금지 (예: "탈취할 수 있습니다"를 두 번 이상 쓰지 말 것)
- 반드시 완전한 문장으로 마무리할 것 (절대 중간에 끊지 말 것)

내용 구성 — 아래 5개 항목을 반드시 각각 1~2문장씩 포함할 것 (항목 번호는 출력하지 말 것):
  1) 탐지 사실: 실제 payload를 직접 인용하며 어느 파라미터에서 탐지되었는지
  2) 통과 원인: 이 payload가 서버 검증을 왜 통과했는지 (입력 처리 코드 관점)
  3) 실행 과정: 브라우저 또는 DB에서 payload가 실제로 어떻게 동작하는지 단계별로
  4) 피해 시나리오: 공격자가 구체적으로 무엇을 탈취/실행할 수 있는지 (쿠키, 세션토큰, DB 데이터 등 구체적으로)
  5) 피해자 관점: 피해자가 눈치채지 못하는 이유와 실제 발생하는 피해

전문 용어는 반드시 괄호로 쉬운 설명 추가 (예: 쿠키(로그인 상태를 저장하는 데이터))

[remediation] — 근본적 해결 중심의 맞춤 대응방안
- 반드시 3~4개 항목
- 각 항목: action(무엇을) + reason(왜 + 어디에 적용하는지 + 코드 예시)

action 작성 규칙:
- 반드시 탐지된 파라미터명과 URL 경로를 직접 언급할 것
  나쁜 예: "모든 입력값에 인코딩 적용"
  좋은 예: "'searchTerm' 파라미터 처리 코드 (/search.html) 에서 출력 시 html.escape() 적용"

reason 작성 규칙 — 반드시 아래 순서로 완결된 문단을 작성할 것:
  1) 탐지된 실제 payload가 왜 현재 코드에서 통과되는지 원인 설명
  2) 어느 처리 시점(입력 수신 / DB 저장 / HTML 출력 등)에 적용해야 하는지 명시
  3) 코드 예시 (Python 또는 JavaScript, 2~4줄) — 코드는 backtick(`) 없이 일반 텍스트로 작성
  4) 이 조치로 해당 payload가 어떻게 무력화되는지 한 문장으로 마무리
- source가 "form"이면 서버에서 POST body를 처리하는 시점 기준으로 설명
- source가 "query"면 GET 쿼리스트링을 처리하는 시점 기준으로 설명
- reason은 반드시 4)번 마무리 문장까지 완성할 것 (절대 중간에 끊지 말 것)
- 한국어만 사용. 한자, 일본어, 중국어 문자 사용 절대 금지.

금지 사항 — 우회 가능한 방법은 절대 단독 대응방안으로 제시하지 말 것:
- 블랙리스트/패턴 매칭 단독 제시 금지 (match(/<script>/), replace('<','') 등)
- XSS: innerHTML 직접 사용 권장 금지, textContent/setAttribute 등 안전한 DOM API 권장
- SQLi: 문자열 필터링 단독 금지, 반드시 Prepared Statement / Parameterized Query 권장
- CSP 단독 제시 금지 — 출력 인코딩과 함께 2차 방어선으로만 언급

근본 해결 우선순위:
XSS  → (1) 출력 컨텍스트별 이스케이프 (HTML/JS/URL 컨텍스트 구분하여 적용)
        (2) 안전한 DOM API 사용 (textContent, setAttribute)
        (3) CSP는 2차 방어선으로만 언급
SQLi → (1) Prepared Statement / Parameterized Query
        (2) ORM 사용 (SQLAlchemy, Django ORM 등)
        (3) DB 에러 메시지 외부 노출 차단

반환 형식 (반드시 이 구조 그대로):
[
  {{
    "severity": "CRITICAL|HIGH|MEDIUM|LOW",
    "ai_description": "5개 항목 포함 완성된 설명",
    "remediation": [
      {{"action": "파라미터명/URL 직접 언급한 구체적 조치", "reason": "원인->적용시점->코드예시->무력화 설명까지 완결된 문단"}},
      {{"action": "...", "reason": "..."}},
      {{"action": "...", "reason": "..."}}
    ]
  }}
]

Severity 기준: CRITICAL=DB유출/인증우회, HIGH=민감정보/세션탈취, MEDIUM=제한적노출/입력반사, LOW=잠재위험"""

    raw = _call_groq(prompt)
    if not raw:
        logger.warning("[VulnAnalyzer] Groq 응답 없음 → ai_description/remediation 빈값으로 처리")
        return []

    try:
        s = raw.find("[")
        e = raw.rfind("]")
        if s != -1 and e > s:
            parsed = json.loads(raw[s:e + 1])
            if isinstance(parsed, list):
                logger.info(f"[VulnAnalyzer] 배치 파싱 성공 → {len(parsed)}개")
                return parsed
    except json.JSONDecodeError:
        pass

    for block in re.findall(r"```(?:json)?\s*(.*?)```", raw, re.DOTALL):
        try:
            parsed = json.loads(block.strip())
            if isinstance(parsed, list):
                return parsed
        except json.JSONDecodeError:
            continue

    logger.warning("[VulnAnalyzer] 배열 파싱 실패 → 빈값으로 처리")
    return []


# ══════════════════════════════════════════════════════════════════
# 3. 요약 생성
# ══════════════════════════════════════════════════════════════════

def _make_summary(target_url: str, vulns: list) -> dict:
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "SAFE": 0}
    for v in vulns:
        sev = v.get("severity", "SAFE").upper()
        if sev in counts:
            counts[sev] += 1

    return {
        "target_url": target_url,
        "scan_date" : datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total"     : len(vulns),
        "critical"  : counts["CRITICAL"],
        "high"      : counts["HIGH"],
        "medium"    : counts["MEDIUM"],
        "low"       : counts["LOW"],
        "safe"      : counts["SAFE"],
    }


def _make_empty_report(target_url: str) -> dict:
    return {
        "summary": {
            "target_url": target_url,
            "scan_date" : datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "total"     : 0,
            "critical"  : 0,
            "high"      : 0,
            "medium"    : 0,
            "low"       : 0,
            "safe"      : 0,
        },
        "vulnerabilities": [],
    }


# ══════════════════════════════════════════════════════════════════
# 4. 전처리
# ══════════════════════════════════════════════════════════════════

def _preprocess(vuln: dict) -> dict:
    return {
        "vuln_type" : _normalize_vuln_type(vuln.get("vuln_type", "")),
        "severity"  : vuln.get("severity", "MEDIUM").upper(),
        "url"       : vuln.get("url", "") or "",
        "parameter" : vuln.get("parameter", "") or "",
        "payload"   : (vuln.get("payload", "") or "")[:200],
        "evidence"  : (vuln.get("evidence", "") or "")[:200],
        "source"    : vuln.get("source", "") or "",
        "reflection": vuln.get("reflection", "") or "",
    }


def _normalize_vuln_type(raw: str) -> str:
    t = raw.lower().strip()
    if "sql" in t or t == "sqli":
        return "sqli"
    if "xss" in t or "cross" in t:
        return "xss"
    return "unknown"


# ══════════════════════════════════════════════════════════════════
# 5. Groq API 호출
# ══════════════════════════════════════════════════════════════════

def _call_groq(prompt: str) -> str:
    try:
        logger.info("[VulnAnalyzer] Groq 호출 중...")
        client = Groq(api_key=GROQ_API_KEY)
        resp = client.chat.completions.create(
            model       = GROQ_MODEL,
            messages    = [{"role": "user", "content": prompt}],
            temperature = 0.3,
            max_tokens  = 4096,
        )
        raw = resp.choices[0].message.content
        logger.info("[VulnAnalyzer] Groq 응답 수신 완료")
        return raw
    except Exception as e:
        logger.error(f"[VulnAnalyzer] Groq 호출 실패: {e}")
        return ""


# ══════════════════════════════════════════════════════════════════
# 6. 위험도 매핑
# ══════════════════════════════════════════════════════════════════

def _map_severity(raw: str) -> Optional[str]:
    if not raw:
        return None
    return SEVERITY_MAP.get(raw.lower().strip().strip('"').strip("'"))


# ══════════════════════════════════════════════════════════════════
# 7. 단독 실행 테스트
# ══════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("=" * 60)
    print("  vuln_analyzer.py 테스트")
    print("=" * 60)

    test_vulns = [
        {
            "severity"  : "MEDIUM",
            "vuln_type" : "xss",
            "evidence"  : "페이로드 반사 확인 (raw)",
            "url"       : "http://zero.webappsecurity.com/search.html",
            "parameter" : "searchTerm",
            "payload"   : "<svg onload=alert(1)>",
            "reflection": "raw",
            "source"    : "form",
        },
        {
            "severity"  : "HIGH",
            "vuln_type" : "sqli",
            "evidence"  : "SQL 에러 노출: you have an error in your sql syntax",
            "url"       : "http://zero.webappsecurity.com/login.html",
            "parameter" : "user_login",
            "payload"   : "' OR 1=1--",
            "reflection": "",
            "source"    : "form",
        },
    ]

    report = analyze_vulnerabilities(test_vulns, target_url="http://zero.webappsecurity.com")

    s = report["summary"]
    print(f"\n대상: {s['target_url']}")
    print(f"총 취약점: {s['total']}개  (치명:{s['critical']} 높음:{s['high']} 보통:{s['medium']} 낮음:{s['low']})")

    for v in report["vulnerabilities"]:
        print(f"\n[{v['id']}] {v['vuln_type'].upper()} — {v['parameter']} ({v['severity']} / CVSS {v['cvss']})")
        print(f"  탐지 근거    : {v['evidence']}")
        print(f"  AI 위험 설명 : {v['ai_description']}")
        print(f"  AI 대응방안  :")
        for i, step in enumerate(v.get("ai_remediation", []), 1):
            print(f"    {i}. {step.get('action', '')}")
            print(f"       → {step.get('reason', '')}")