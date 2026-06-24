import json
from crawler.crawler import BFSCrawler
from urllib.parse import urlparse

def crawl(start_url, target_domain=None, progress_callback=None):
    """
    애플리케이션의 핵심 크롤링 인터페이스
    """
    if target_domain is None:
        target_domain = urlparse(start_url).netloc

    crawler = BFSCrawler(start_url, target_domain)
    
    # crawler의 run 메서드에 progress_callback을 전달합니다.
    pages = crawler.run(progress_callback=progress_callback)
    return pages

def crawl_to_json(start_url, target_domain=None):
    pages = crawl(start_url, target_domain)
    return json.dumps(pages, ensure_ascii=False)

if __name__ == "__main__":
    # 터미널 단독 실행 테스트용
    url = input("크롤링할 URL 입력: ")
    if not url.startswith("http"): url = "https://" + url
    
    print("\n[테스트] 크롤링 시작...")
    results = crawl(url)
    print(f"\n총 {len(results)}개의 페이지를 수집했습니다.")
