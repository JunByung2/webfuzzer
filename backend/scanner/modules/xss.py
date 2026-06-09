"""
scanner/modules/xss.py

XSS 응답 분석 모듈
injector로부터 (response, elapsed, url, parameter, payload, source)를 받아서
팀원 코드 detect_reflection + RiskAnalyzer로 분석 후 VulnResult 반환

이 파일이 하는 것: 응답 분석만
이 파일이 안 하는 것: HTTP 요청, 페이로드 생성 (injector 담당)
"""

from utils.analyzer import ResponseAnalyzer, RiskAnalyzer
from models.vuln_result import VulnResult, Severity


class XSSModule:

    def __init__(self):
        self.response_analyzer = ResponseAnalyzer()
        self.risk_analyzer     = RiskAnalyzer()

    def analyze(
        self,
        response,
        elapsed:   float,
        url:       str = "",
        parameter: str = "",
        payload:   str = "",
        source:    str = "",
    ) -> VulnResult:
        """
        injector에서 받은 응답을 분석해서 XSS 취약 여부 판정

        판정 흐름:
            1. detect_reflection → 페이로드가 응답에 반사됐는지 확인
            2. 반사 확인되면 RiskAnalyzer로 severity 판정
            3. VulnResult 반환

        Args:
            response  : http_client가 반환한 requests.Response 객체
            elapsed   : 응답 시간 (초)
            url       : 요청한 URL
            parameter : 페이로드를 삽입한 파라미터 키  ex) "lb-search"
            payload   : 실제 삽입한 페이로드           ex) "<script>alert(1)</script>"
            source    : "query" | "form"

        Returns:
            VulnResult — is_vulnerable()가 True면 취약
        """
        # ① 페이로드 반사 여부 확인 (팀원 코드)
        is_reflected, reflection_type = self.response_analyzer.detect_reflection(
            response.text, payload
        )

        if not is_reflected:
            return VulnResult(
                severity   = Severity.SAFE,
                vuln_type  = "xss",
                evidence   = "반사 없음",
                url        = url,
                parameter  = parameter,
                payload    = payload,
                source     = source,
            )

        # ② 반사 확인됐으면 severity 판정 (팀원 코드)
        result = self.risk_analyzer.assess_risk(
            response  = response,
            elapsed   = elapsed,
            payload   = payload,
            parameter = parameter,
            url       = url,
        )

        # ③ reflection_type 기록 (raw / html_encoded / url_encoded / json_reflected)
        result.reflection = reflection_type or ""
        result.source     = source
        result.vuln_type  = "xss"

        # ④ assess_risk가 SAFE로 판정했더라도 반사는 확인됐으므로 최소 MEDIUM
        #    ex) 페이로드가 반사됐지만 <script>alert 형태가 아닌 경우
        if result.severity == Severity.SAFE:
            result.severity = Severity.MEDIUM
            result.evidence = f"페이로드 반사 확인 ({reflection_type}) — 브라우저 실행 여부 수동 검증 필요"

        return result