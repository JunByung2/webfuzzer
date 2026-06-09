"""
utils/analyzer.py

응답 분석 + 위험도 판단 로직
- 팀원 원본 코드 (detect_error_message, detect_reflection, RiskAnalyzer) 유지
- 반환 타입 통일, HTML/URL/JSON 인코딩 탐지, dataclass 반환 패치 추가
"""

import html
import json
import urllib.parse
from dataclasses import dataclass, field
from enum import Enum
from models.vuln_result import VulnResult, Severity


# ------------------------------------------------------------------ #
#  패치 추가 — 공통 타입 정의                                           #
#  모든 파일이 이 타입을 import해서 사용                                #
# ------------------------------------------------------------------ #

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    SAFE     = "SAFE"


# @dataclass
# class VulnResult:
#     """
#     스캔 결과 단위 — DB INSERT에 바로 매핑되는 구조
#     severity, vuln_type, evidence 세 필드가 핵심
#     """
#     severity:   Severity
#     vuln_type:  str              # "sqli" | "xss" | "none"
#     evidence:   str              # 판정 근거 (어떤 키워드/페이로드로 탐지됐는지)
#     url:        str  = ""
#     parameter:  str  = ""        # 취약한 파라미터 키
#     payload:    str  = ""        # 실제 사용된 페이로드
#     reflection: str  = ""        # 반사 방식 (raw / html_encoded / url_encoded / json_reflected)


# ------------------------------------------------------------------ #
#  팀원 원본 코드 — ResponseAnalyzer                                   #
# ------------------------------------------------------------------ #

class ResponseAnalyzer:

    def detect_error_message(self, response_text: str) -> tuple[bool, str | None]:
        """
        응답에 DB 에러 메시지가 있는지 확인 (SQLi 탐지용)
        페이로드 주입 후 응답에 DB 오류 문자열이 있으면 취약한 것
        - 팀원 원본 유지 + 키워드 보강 패치
        """
        error_keywords = [
            # 팀원 원본
            "you have an error in your sql syntax",   # MySQL 문법 오류
            "warning: mysql",                         # MySQL 경고
            "unclosed quotation mark",                # MSSQL 오류
            "quoted string not properly terminated",  # Oracle 오류
            "pg_query",                               # PostgreSQL 오류
            "sqlite_error",                           # SQLite 오류
            "odbc driver",                            # ODBC 오류
            # 패치 추가
            "syntax error",
            "sql syntax",
            "invalid query",
            "division by zero",                       # 에러 기반 SQLi
            "mysql_fetch_array",                      # PHP MySQL 함수 노출
            "ora-00933",                              # Oracle 오류코드
            "postgresql query failed",
        ]
        response_lower = response_text.lower()        # 대소문자 구분 없이 비교하려고 소문자로 통일
        for keyword in error_keywords:
            if keyword in response_lower:             # 에러 키워드가 응답에 포함되면
                return True, keyword                  # 취약 True + 발견된 키워드 반환
        return False, None                            # 에러 없으면 False 반환

    def detect_reflection(self, response_text: str, payload: str) -> tuple[bool, str | None]:
        """
        주입한 페이로드가 응답에 그대로 반사됐는지 확인 (XSS 탐지용)
        ex) <script>alert(1)</script> 를 주입했는데 응답 HTML에 그대로 있으면 취약
        - 팀원 원본 유지 + HTML/URL/JSON 인코딩 탐지 패치
        """
        # 팀원 원본 — 원본 페이로드 그대로 반사
        if payload in response_text:                  # 페이로드가 응답에 그대로 있으면
            return True, "raw"                        # 반사된 것 → XSS 취약 가능성

        # 패치 추가 — HTML 인코딩된 경우 (&lt;script&gt; 등)
        html_encoded = html.escape(payload)
        if html_encoded != payload and html_encoded in response_text:
            return True, "html_encoded"

        # 패치 추가 — URL 인코딩된 경우
        url_encoded = urllib.parse.quote(payload)
        if url_encoded != payload and url_encoded in response_text:
            return True, "url_encoded"

        # 패치 추가 — JSON 응답 안에 반사된 경우
        try:
            json_body = json.loads(response_text)
            if payload in str(json_body):
                return True, "json_reflected"
        except (json.JSONDecodeError, ValueError):
            pass

        return False, None                            # 반사 안 됨 → 안전


# ------------------------------------------------------------------ #
#  팀원 원본 코드 — RiskAnalyzer                                       #
# ------------------------------------------------------------------ #

class RiskAnalyzer:

    def assess_risk(
        self,
        response,
        elapsed: float,
        payload:   str = "",
        parameter: str = "",
        url:       str = "",
    ) -> VulnResult:
        """
        응답 내용 + 경과 시간으로 취약 여부와 심각도 판정
        - 팀원 원본 판정 기준 유지
        - 반환 타입을 문자열 → VulnResult dataclass로 패치 (DB INSERT 대응)
        """
        body = response.text.lower()

        # 팀원 원본 — CRITICAL
        # 패치: "admin"+"password" 단순 조합은 로그인 페이지 오탐 가능성 높아
        #       실제 DB 내용 유출 신호(@@version, table_name 등)로 교체
        db_leak_signals = [
            "root:",
            "information_schema",
            "table_name",
            "@@version",
        ]
        if any(s in body for s in db_leak_signals):
            return VulnResult(
                severity  = Severity.CRITICAL,
                vuln_type = "sqli",
                evidence  = "DB 내용 유출 의심 — " + next(s for s in db_leak_signals if s in body),
                url       = url,
                parameter = parameter,
                payload   = payload,
            )

        # 팀원 원본 — HIGH
        if "<script>alert" in body or "onerror=alert" in body:
            return VulnResult(
                severity  = Severity.HIGH,
                vuln_type = "xss",
                evidence  = "XSS 페이로드 반사 확인",
                url       = url,
                parameter = parameter,
                payload   = payload,
            )

        # 팀원 원본 — MEDIUM
        sql_errors = [
            "mysql_fetch_array",
            "ora-00933",
            "postgresql query failed",
            "you have an error in your sql syntax",
            "warning: mysql",
        ]
        for err in sql_errors:
            if err in body:
                return VulnResult(
                    severity  = Severity.MEDIUM,
                    vuln_type = "sqli",
                    evidence  = f"SQL 에러 노출: {err}",
                    url       = url,
                    parameter = parameter,
                    payload   = payload,
                )

        # 팀원 원본 — LOW
        if elapsed > 5.0:
            return VulnResult(
                severity  = Severity.LOW,
                vuln_type = "sqli",
                evidence  = f"응답 지연 {elapsed:.1f}s — 시간 기반 SQLi 의심",
                url       = url,
                parameter = parameter,
                payload   = payload,
            )

        # 팀원 원본 — SAFE
        return VulnResult(
            severity  = Severity.SAFE,
            vuln_type = "none",
            evidence  = "이상 없음",
            url       = url,
            parameter = parameter,
            payload   = payload,
        )