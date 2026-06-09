from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode

class URLFilter:
    def __init__(self, target_domain):
        self.visited_urls = set()
        self.target_domain = target_domain.lower()

    def normalize_url(self, url):
        """URL 정규화 (중복 제거 핵심)"""


        try:
            parsed = urlparse(url)

            # 1. fragment 제거
            fragment_removed = parsed._replace(fragment="")

            # 2. scheme 통일 (http → https)
            scheme = "https"

            # 3. netloc 소문자 처리
            netloc = fragment_removed.netloc.lower()

            # 4. trailing slash 제거
            path = fragment_removed.path.rstrip("/")

            # 5. query 파라미터 정렬 (중복 방지)
            query = urlencode(sorted(parse_qsl(fragment_removed.query)))

            normalized = urlunparse((
                scheme,
                netloc,
                path,
                "",     # params 제거
                query,
                ""      # fragment 제거
            ))

            return normalized

        except Exception as e:
            print(f"[정규화 오류] {url} | {e}")
            return None

    def is_valid(self, url):
        """방문 가능한 URL인지 최종 판별"""
        clean_url = self.normalize_url(url)

        if not clean_url:
            return False

        if not self._is_same_domain(clean_url):
            return False

        if clean_url in self.visited_urls:
            return False

        return True

    def _is_same_domain(self, url):
        """도메인이 정확히 일치하는지 확인"""
        try:
            parsed_url = urlparse(url)
            netloc = parsed_url.netloc

            return netloc == self.target_domain or \
                   netloc.endswith("." + self.target_domain)

        except Exception as e:
            print(f"[도메인 검사 오류] {url} | {e}")
            return False

    def add_visited(self, url):
        """방문 URL 저장"""
        clean_url = self.normalize_url(url)
        if clean_url:
            self.visited_urls.add(clean_url)


##########실행 테스트

def test_url_filter():
    # 목표 도메인
    filter = URLFilter("example.com")

    # parse.py가 뽑았다고 가정한 URL들
    parsed_urls = [
        "https://example.com",
        "https://example.com/about",
        "https://example.com/about#team",
        "http://example.com/about/",
        "https://example.com/about?a=1&b=2",
        "https://example.com/about?b=2&a=1",
        "https://sub.example.com/page",
        "https://evil-example.com/hack",
        "https://google.com",
    ]

    print("=== URL FILTER TEST START ===")

    for url in parsed_urls:
        print(f"\n[입력] {url}")

        if filter.is_valid(url):
            print(" → 통과 (크롤링 대상)")
            filter.add_visited(url)
        else:
            print(" → 차단됨")

    print("\n=== 최종 방문 URL ===")
    for v in filter.visited_urls:
        print(v)


if __name__ == "__main__":
    test_url_filter()
            