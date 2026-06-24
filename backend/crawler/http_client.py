"""
crawler/http_client.py

크롤러 HTTP 요청

변경사항
────────────────────────────────────────────────────────────────────────
 [제거] time.sleep(REQUEST_DELAY)
   → 매 요청마다 블로킹 슬립 → 병렬 fetch 효과 완전 상쇄.

 [추가] fetch_urls() — URL 목록을 ThreadPoolExecutor로 병렬 fetch
   → 크롤러는 보통 수십~수백 URL을 순차 처리하므로 가장 효과가 큼.

 [유지] fetch_url() — 단일 URL 호출은 기존 시그니처 유지 (하위 호환).
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import requests
import time
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed
from requests.adapters import HTTPAdapter
from config.config import REQUEST_TIMEOUT, MAX_RETRIES

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_POOL_SIZE    = 20
_DEFAULT_WORKERS = 20

# 스레드 로컬 세션 (스레드마다 독립 커넥션 풀)
import threading
_thread_local = threading.local()


def _get_session() -> requests.Session:
    if not hasattr(_thread_local, "session"):
        session = requests.Session()
        adapter = HTTPAdapter(
            pool_connections = _POOL_SIZE,
            pool_maxsize     = _POOL_SIZE,
        )
        session.mount("http://",  adapter)
        session.mount("https://", adapter)
        _thread_local.session = session
    return _thread_local.session


def fetch_url(url: str) -> str | None:
    """
    단일 URL fetch. 기존 시그니처 유지.
    슬립 제거 — rate-limit이 필요하면 호출부에서 조절할 것.
    """
    session = _get_session()

    for attempt in range(MAX_RETRIES):
        try:
            response = session.get(
                url,
                timeout = REQUEST_TIMEOUT,
                verify  = False,
            )
            status = response.status_code

            if status == 200:
                print(f"[200] 정상: {url}")
                return response.text

            elif status in (301, 302):
                print(f"[{status}] 리다이렉트: {url}")
                return None

            elif status == 403:
                print(f"[403] 접근 금지 (차단 가능성): {url}")
                return None

            elif status == 404:
                print(f"[404] 페이지 없음: {url}")
                return None

            elif status >= 500:
                print(f"[{status}] 서버 오류 (취약점 가능성): {url}")
                return None

            else:
                print(f"[{status}] 기타 상태: {url}")
                return None

        except requests.exceptions.Timeout:
            print(f"[TIMEOUT] 재시도 {attempt + 1}/{MAX_RETRIES}: {url}")
            if attempt + 1 == MAX_RETRIES:
                print(f"[TIMEOUT] 최대 재시도 초과: {url}")
                return None

        except requests.exceptions.RequestException as e:
            print(f"[ERROR] 요청 실패: {url} | {e}")
            return None

    return None


def fetch_urls(
    urls: list[str],
    max_workers: int = _DEFAULT_WORKERS,
) -> dict[str, str | None]:
    """
    URL 목록을 병렬로 fetch한다.

    Returns:
        {url: html_text | None}
    """
    results: dict[str, str | None] = {}
    results_lock = threading.Lock()

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_url = {executor.submit(fetch_url, url): url for url in urls}

        for future in as_completed(future_to_url):
            url = future_to_url[future]
            try:
                html = future.result()
            except Exception as e:
                print(f"[ERROR] {url} | {e}")
                html = None
            with results_lock:
                results[url] = html

    return results


if __name__ == "__main__":
    # 단일 fetch 테스트
    print("=== 200 테스트 ===")
    html = fetch_url("https://www.youtube.com/")
    print("반환값:", html[:200] if html else None)

    print("\n=== 404 테스트 ===")
    html = fetch_url("https://example.com/없는페이지")
    print("반환값:", html)

    # 병렬 fetch 테스트
    print("\n=== 병렬 fetch 테스트 ===")
    test_urls = [
        "https://www.youtube.com/",
        "https://example.com/",
        "https://httpbin.org/get",
    ]
    start = time.time()
    results = fetch_urls(test_urls)
    print(f"총 소요: {time.time() - start:.2f}초")
    for u, h in results.items():
        print(f"  {u} → {'OK' if h else 'None'}")
