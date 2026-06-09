"""
scanner/http_client.py

HTTP 요청 중앙 관리
- 모든 모듈(xss.py, sqli.py)은 requests를 직접 쓰지 않고 이 클라이언트를 사용
- 타임아웃, User-Agent 헤더 여기서 일괄 관리

변경사항
────────────────────────────────────────────────────────────────────────
 [제거] time.sleep(RATE_LIMIT_DELAY)
   → 매 요청마다 0.5초 블로킹 → 500요청 × 0.5초 = 250초 낭비.
     병렬화 효과를 완전히 상쇄하는 구조였음.
     필요 시 Injector 레벨에서 선택적으로 적용할 것.

 [추가] 스레드 로컬 세션 (_thread_local)
   → 스레드마다 독립 Session을 생성해 커넥션 풀 경합 제거.
   → requests.Session은 스레드 세이프하지만 내부 urllib3 풀(기본 10)이
     20+ 스레드에서 병목이 됨.

 [추가] HTTPAdapter 커넥션 풀 확장
   → pool_connections=20, pool_maxsize=20 으로 workers 수에 맞춤.
"""

import threading
import urllib3
import requests
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from requests import Response
from requests.adapters import HTTPAdapter
from backend.config.config import (
    REQUEST_TIMEOUT,   # 8  — 요청 타임아웃 (초)
    USER_AGENT,        # Mozilla/5.0 ...
)
from urllib.parse import urlsplit, urlunsplit

# 스레드마다 독립 Session을 보관
_thread_local = threading.local()

# 커넥션 풀 크기 — Injector의 max_workers와 맞춤
_POOL_SIZE = 20


def _get_session(user_agent: str, cookies: dict, headers: dict) -> requests.Session:
    """
    현재 스레드의 Session을 반환한다.
    처음 호출 시 생성하며, 커넥션 풀을 _POOL_SIZE로 확장한다.
    """
    if not hasattr(_thread_local, "session"):
        session = requests.Session()
        adapter = HTTPAdapter(
            pool_connections = _POOL_SIZE,
            pool_maxsize     = _POOL_SIZE,
        )
        session.mount("http://",  adapter)
        session.mount("https://", adapter)
        session.headers.update({"User-Agent": user_agent})
        _thread_local.session = session

    # 쿠키·헤더는 매번 갱신 (set_cookies/set_headers 반영)
    if cookies:
        _thread_local.session.cookies.update(cookies)
    if headers:
        _thread_local.session.headers.update(headers)

    return _thread_local.session


class HttpClient:

    def __init__(self):
        self._extra_cookies: dict = {}
        self._extra_headers: dict = {}

    @property
    def _session(self) -> requests.Session:
        return _get_session(USER_AGENT, self._extra_cookies, self._extra_headers)

    # ------------------------------------------------------------------ #
    #  GET 요청                                                            #
    # ------------------------------------------------------------------ #

    def get(self, url: str, params: dict | None = None) -> tuple[Response | None, float]:
        import time
        try:
            start    = time.time()
            clean_url = urlunsplit(urlsplit(url)._replace(query=""))

            response = self._session.get(
                clean_url,
                params  = params or {},
                timeout = REQUEST_TIMEOUT,
                allow_redirects = True,
                verify  = False,
            )
            elapsed = time.time() - start
            return response, elapsed

        except requests.exceptions.Timeout:
            print(f"[HTTP TIMEOUT] GET {url}")
            return None, float(REQUEST_TIMEOUT)

        except requests.exceptions.RequestException as e:
            print(f"[HTTP ERROR] GET {url} | {type(e).__name__}: {e}")
            return None, 0.0

    # ------------------------------------------------------------------ #
    #  POST 요청                                                           #
    # ------------------------------------------------------------------ #

    def post(self, url: str, data: dict | None = None) -> tuple[Response | None, float]:
        import time
        try:
            start    = time.time()
            response = self._session.post(
                url,
                data    = data or {},
                timeout = REQUEST_TIMEOUT,
                allow_redirects = True,
                verify  = False,
            )
            elapsed = time.time() - start
            return response, elapsed

        except requests.exceptions.Timeout:
            print(f"[HTTP TIMEOUT] POST {url}")
            return None, float(REQUEST_TIMEOUT)

        except requests.exceptions.RequestException as e:
            print(f"[HTTP ERROR] POST {url} | {type(e).__name__}: {e}")
            return None, 0.0

    # ------------------------------------------------------------------ #
    #  method 문자열로 분기                                                #
    # ------------------------------------------------------------------ #

    def request(
        self,
        method: str,
        url:    str,
        params: dict | None = None,
    ) -> tuple[Response | None, float]:
        if method.upper() == "POST":
            return self.post(url, data=params)
        return self.get(url, params=params)

    # ------------------------------------------------------------------ #
    #  세션 쿠키·헤더 주입 (로그인 필요 페이지 대응)                        #
    # ------------------------------------------------------------------ #

    def set_cookies(self, cookies: dict) -> None:
        self._extra_cookies.update(cookies)

    def set_headers(self, headers: dict) -> None:
        self._extra_headers.update(headers)