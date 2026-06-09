from collections import deque
from urllib.parse import urlparse, parse_qs, urljoin
from bs4 import BeautifulSoup

from backend.crawler.url_filter import URLFilter
from backend.crawler.http_client import fetch_url
from backend.config.config import MAX_DEPTH, MAX_PAGES

class BFSCrawler:
    def __init__(self, start_url, target_domain, max_depth=MAX_DEPTH):
        self.target_domain = target_domain
        self.max_depth = max_depth
        self.max_pages = MAX_PAGES # 진행률 계산의 기준

        self.queue = deque([(start_url, 0)])
        self.filter = URLFilter(target_domain)
        self.filter.add_visited(start_url)

    def run(self, progress_callback=None):
        pages = []

        while self.queue:
            current_url, current_depth = self.queue.popleft()

            # 최대 수집 개수 도달 시 중단
            if len(pages) >= self.max_pages:
                break

            if current_depth > self.max_depth:
                continue

            # [진행률 보고] 현재 수집된 페이지 수 기반 % 계산
            if progress_callback:
                current_p = int((len(pages) / self.max_pages) * 100)
                progress_callback(min(current_p, 99)) # 크롤링 단계 내의 % 전송

            html = fetch_url(current_url)
            if html is None:
                continue

            soup = BeautifulSoup(html, "html.parser")

            # 링크 추출
            links = []
            for tag in soup.find_all("a", href=True):
                full_url = urljoin(current_url, tag["href"])
                links.append(full_url)

            # Form 추출
            forms = []
            for form in soup.find_all("form"):
                action = form.get("action", "")
                action_url = urljoin(current_url, action)
                method = form.get("method", "GET").upper()
                inputs = [t.get("name") for t in form.find_all(["input", "textarea", "select"]) 
                          if t.get("name") and t.get("type") not in ("hidden", "submit", "button")]
                forms.append({"action": action_url, "method": method, "inputs": inputs})

            # 쿼리 파라미터 추출
            parsed = urlparse(current_url)
            query_params = list(parse_qs(parsed.query).keys())

            # 결과 저장
            pages.append({
                "url": current_url,
                "depth": current_depth,
                "forms": forms,
                "links": links,
                "query_params": query_params
            })

            # BFS 확장
            for link in links:
                if link.endswith((".jpg", ".png", ".pdf", ".zip")):
                    continue
                if self.filter.is_valid(link):
                    self.filter.add_visited(link)
                    self.queue.append((link, current_depth + 1))

        # 크롤링 단계 최종 완료 보고
        if progress_callback:
            progress_callback(100)
            
        return pages