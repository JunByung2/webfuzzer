"""
scanner/orchestrator.py

크롤러 JSON 파싱 → 스캔 대상 추출 → injector에 위임 → 결과 수집
DB 저장은 하지 않음 — main.py가 결과를 받아서 저장
"""

from urllib.parse import urlparse, parse_qs

from scanner.injector import Injector
from scanner.payload_loader import get_xss_payloads, get_sqli_payloads
from models.vuln_result import VulnResult


class Orchestrator:
    def __init__(self, db_connection=None):
        self.injector = Injector()
        self.db = db_connection

    def _get_ordered_payloads(self, vuln_type: str, url: str) -> list:
        if self.db:
            try:
                from scanner.payload_recommender import recommend_payload_order
                result = recommend_payload_order(self.db, vuln_type, url)
                payloads = [r["payload"] for r in result.get("recommended_order", [])]
                if payloads:
                    print(f"[PayloadAI] {vuln_type} 추천 {len(payloads)}개 로드")
                    return payloads
            except Exception as e:
                import traceback
                print(f"[PayloadAI] 추천 실패 타입: {type(e).__name__}")
                print(f"[PayloadAI] 추천 실패 내용: {e}")
                traceback.print_exc()

        return get_xss_payloads() if vuln_type == "xss" else get_sqli_payloads()

    def run(self, crawler_json: dict) -> list:
        """
        크롤러 JSON을 받아서 스캔 실행 후 VulnResult 리스트 반환

        Args:
            crawler_json: 크롤러가 넘겨주는 JSON 전체

        Returns:
            발견된 취약점 VulnResult 리스트 (SAFE 제외, 중복 제거)
        """

        all_results = []

        # 스캔 전체에서 한 번만 추천받기 (xss 1회 + sqli 1회)
        target_url    = crawler_json.get("url", "")
        xss_payloads  = self._get_ordered_payloads("xss",  target_url)
        sqli_payloads = self._get_ordered_payloads("sqli", target_url)

        for page in crawler_json.get("results", []):
            url = page.get("url", "")

            query_params = self._extract_query_params(
                url,
                page.get("query_params", [])
            )

            forms = self._extract_forms(page.get("forms", []))

            # URL 파라미터 스캔
            if query_params:
                print(f"[*] {url} → query 파라미터 스캔 중... {list(query_params.keys())}")

                results  = self.injector.run_xss_with_payloads(
                    url=url, params=query_params, method="GET",
                    source="query", payloads=xss_payloads,
                )
                results += self.injector.run_sqli_with_payloads(
                    url=url, params=query_params, method="GET",
                    source="query", payloads=sqli_payloads,
                )

                all_results += results

            # 폼 스캔
            for form in forms:
                print(f"[*] {form['action']} → form 스캔 중... {list(form['inputs'].keys())}")

                results  = self.injector.run_xss_with_payloads(
                    url=form["action"], params=form["inputs"], method=form["method"],
                    source="form", payloads=xss_payloads,
                )
                results += self.injector.run_sqli_with_payloads(
                    url=form["action"], params=form["inputs"], method=form["method"],
                    source="form", payloads=sqli_payloads,
                )

                all_results += results

        # ── 중복 제거: (url, parameter, vuln_type) 기준으로 첫 번째만 유지 ──
        seen   = set()
        deduped = []
        for r in all_results:
            d   = r.to_dict() if hasattr(r, "to_dict") else r
            key = (
                d.get("url", ""),
                d.get("parameter", ""),
                d.get("vuln_type") or d.get("vulnerability", ""),
            )
            if key not in seen:
                seen.add(key)
                deduped.append(r)
            else:
                print(f"[Orchestrator] 중복 제거: {key}")

        print(f"[Orchestrator] 최종 결과: {len(all_results)}개 → 중복 제거 후 {len(deduped)}개")
        return deduped

    # ------------------------------------------------------------------
    # 파싱 메서드
    # ------------------------------------------------------------------

    def _extract_query_params(self, url: str, raw: list) -> dict:
        """
        URL 자체에 ?query=... 가 있으면 직접 파싱
        크롤러가 query_params를 채워줬으면 그걸 사용
        """

        parsed = urlparse(url)

        if parsed.query:
            return {
                k: v[0]
                for k, v in parse_qs(parsed.query).items()
            }

        if raw and isinstance(raw[0], dict):
            return {
                item["name"]: item.get("value", "")
                for item in raw
            }

        return {}

    def _extract_forms(self, raw_forms: list) -> list:
        """
        forms 구조 정규화

        inputs: [] → skip
        inputs: ["lb-search"] → {"lb-search": ""}
        inputs: ["tier", "tier"] → {"tier": ""}
        inputs: [{"name": "q", ...}] → {"q": "value"}
        """

        result = []

        for form in raw_forms:
            action = form.get("action", "")
            method = form.get("method", "GET").upper()
            inputs = form.get("inputs", [])

            if not action or not inputs:
                continue

            if isinstance(inputs[0], str):
                params = {
                    name: ""
                    for name in inputs
                }

            elif isinstance(inputs[0], dict):
                params = {
                    i["name"]: i.get("value", "")
                    for i in inputs
                }

            else:
                continue

            result.append({
                "action": action,
                "method": method,
                "inputs": params,
            })

        return result