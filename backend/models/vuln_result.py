"""
models/vuln_result.py

스캔 결과 및 메타데이터 타입 정의
- 모든 파일이 VulnResult, Severity, ScanReport를 여기서 import해서 사용
- DB INSERT에 바로 매핑되는 구조로 설계됨 (.to_dict() 메서드 활용)
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import List, Optional


class Severity(str, Enum):
    """
    취약점 심각도 등급
    str 상속 → DB 저장 시 .value 없이 바로 문자열로 INSERT 가능
    ex) "CRITICAL" / "HIGH" / "MEDIUM" / "LOW" / "SAFE"
    """
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    SAFE     = "SAFE"


@dataclass
class VulnResult:
    """
    개별 스캔 결과 단위 (취약점 상세 정보)

    필수 필드
    ---------
    severity  : 심각도 등급 (Severity enum)
    vuln_type : 취약점 종류 "sqli" | "xss" | "none"
    evidence  : 판정 근거 — 어떤 키워드/페이로드로 탐지됐는지 기록

    선택 필드 (DB 저장 시 함께 기록)
    ---------------------------------
    url        : 요청한 URL
    parameter  : 취약한 파라미터 키  ex) "id"
    payload    : 실제 사용된 페이로드 ex) "' OR 1=1--"
    reflection : XSS 반사 방식
                 "raw" | "html_encoded" | "url_encoded" | "json_reflected"
    source     : 파라미터 출처 "query" | "form"
    scanned_at : 스캔 시각 (자동 기록)
    """
    severity:   Severity
    vuln_type:  str
    evidence:   str

    url:        str      = ""
    parameter:  str      = ""
    payload:    str      = ""
    reflection: str      = ""
    source:     str      = ""
    scanned_at: datetime = field(default_factory=datetime.utcnow)

    # ------------------------------------------------------------------ #
    #  편의 메서드                                                       #
    # ------------------------------------------------------------------ #

    def is_vulnerable(self) -> bool:
        """SAFE가 아니면 취약한 것으로 판정"""
        return self.severity != Severity.SAFE

    def to_dict(self) -> dict:
        """
        DB repository에서 INSERT할 때 사용 (자식 테이블용)
        datetime 객체는 JSON 및 DB 호환성을 위해 ISO 포맷 문자열로 변환합니다.
        """
        d = asdict(self)
        d["severity"] = self.severity.value
        d["scanned_at"] = self.scanned_at.isoformat()
        return d

    def __str__(self) -> str:
        return (
            f"[{self.severity.value}] {self.vuln_type.upper()} | "
            f"url={self.url} param={self.parameter} | {self.evidence}"
        )


@dataclass
class ScanReport:
    """
    스캔 세션 전체 결과물 (메타데이터 + 취약점 리스트)
    크롤러가 넘겨준 데이터를 기반으로 생성하며, 팀원이 DB에 최종 저장할 때 사용합니다.
    """
    target_url: str
    start_time: datetime
    end_time:   Optional[datetime] = None
    duration:   float = 0.0
    page_count: int = 0
    status:     str = "success"
    
    # 실제 발견된 취약점 리스트 (VulnResult 객체들이 담김)
    results:    List[VulnResult] = field(default_factory=list)

    def finalize(self):
        """
        스캔 종료 시 호출하여 종료 시간과 총 소요 시간을 계산합니다.
        """
        self.end_time = datetime.utcnow()
        self.duration = (self.end_time - self.start_time).total_seconds()

    def to_dict(self) -> dict:
        """
        전체 데이터를 DB 저장 및 JSON 출력용 딕셔너리로 변환합니다.
        팀원은 이 결과를 받아서 부모 테이블(scans)과 자식 테이블(vulnerabilities)에 나누어 담습니다.
        """
        return {
            "target_url": self.target_url,
            "start_time": self.start_time.isoformat(),
            "end_time":   self.end_time.isoformat() if self.end_time else None,
            "duration":   self.duration,
            "page_count": self.page_count,
            "status":     self.status,
            "results":    [r.to_dict() for r in self.results]
        }