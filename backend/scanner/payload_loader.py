"""
scanner/payload_loader.py

payloads.json을 로드해서 스캔 모듈에 페이로드를 공급
- 앱 시작 시 한 번만 로드 (싱글톤 패턴)
- xss.py / sqli.py / injector.py 에서 이 모듈을 import해서 사용
"""

import json
import os

# payloads.json 경로 — 이 파일 기준 상위 디렉토리
_PAYLOAD_PATH = os.path.join(os.path.dirname(__file__), "payloads.json")

# 앱 시작 시 한 번만 로드
_cache: dict | None = None


def _load() -> dict:
    global _cache
    if _cache is None:
        with open(_PAYLOAD_PATH, "r", encoding="utf-8") as f:
            _cache = json.load(f)
    return _cache


def get_sqli_payloads() -> list[str]:
    """
    SQLi 페이로드 전체 반환
    injector.py / sqli.py 에서 호출
    """
    return _load().get("sqli", [])


def get_xss_payloads() -> list[str]:
    """
    XSS 페이로드 전체 반환
    injector.py / xss.py 에서 호출
    """
    return _load().get("xss", [])