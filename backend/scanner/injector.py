"""
scanner/injector.py

병렬화 전략
───────────────────────────────────────────────────────────────────────
 페이지 5 × 공격유형 2 × 키 5 × 페이로드 10 = 최대 500 요청

 [변경] 페이로드 브로드캐스트 방식
   페이로드 하나(+뮤테이션)를 모든 입력 포인트(키)에 동시에 주입.
   → 같은 페이로드로 모든 키를 한 라운드에 커버.
   → 취약점이 발견된 키는 found_keys에 등록 → 이후 라운드에서 스킵.
   → 모든 키가 발견되면 남은 페이로드 순회를 조기 종료.

 흐름:
   for base_payload in payloads:
       for payload in mutations(base_payload):
           [key1, key2, key3 ...] ← ThreadPoolExecutor 동시 실행
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed, Future
from typing import Optional

from scanner.http_client import HttpClient
from scanner.payload_loader import get_xss_payloads, get_sqli_payloads
from utils.mutator import PayloadMutator
from models.vuln_result import VulnResult


_DEFAULT_WORKERS = 20


class Injector:

    def __init__(self, max_workers: int = _DEFAULT_WORKERS):
        self.mutator     = PayloadMutator()
        self.max_workers = max_workers

    # ── 정적 페이로드 ────────────────────────────────────────────────

    def run_xss(self, url, params, method="GET", source="") -> list[VulnResult]:
        return self._run(url, params, method, source, get_xss_payloads(), "xss")

    def run_sqli(self, url, params, method="GET", source="") -> list[VulnResult]:
        return self._run(url, params, method, source, get_sqli_payloads(), "sqli")

    def run_all(self, url, params, method="GET", source="") -> list[VulnResult]:
        results = []
        results += self.run_xss(url, params, method, source)
        results += self.run_sqli(url, params, method, source)
        return results

    # ── AI 동적 페이로드 ─────────────────────────────────────────────
    # orchestrator에서 AI 추천 순서로 생성된 페이로드를 주입하는 메서드.

    def run_xss_with_payloads(self, url, params, method="GET", source="", payloads=None) -> list[VulnResult]:
        if not payloads:
            return []
        return self._run(url, params, method, source, payloads, "xss")

    def run_sqli_with_payloads(self, url, params, method="GET", source="", payloads=None) -> list[VulnResult]:
        if not payloads:
            return []
        return self._run(url, params, method, source, payloads, "sqli")

    # ── 공통 주입 로직 (페이로드 브로드캐스트) ───────────────────────

    def _run(self, url, params, method, source, payloads, attack_type) -> list[VulnResult]:

        # print(f"\n[Injector] ── 페이로드 삽입 순서 ({attack_type.upper()}) ──")
        # for i, p in enumerate(payloads[:10], 1):  # 최대 10개만 출력
        #     print(f"  [{i}] {p[:60]}")
        # print(f"[Injector] 총 {len(payloads)}개 페이로드 순서대로 삽입 시작\n")


        results:    list[VulnResult] = []
        found_keys: set[str]         = set()   # 취약점 발견 완료된 키 → 이후 라운드 스킵
        all_keys  = list(params.keys())

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:

            for base_payload in payloads:

                # 모든 키에서 취약점 발견 → 남은 페이로드 불필요
                if found_keys >= set(all_keys):
                    break

                if attack_type == "xss":
                    mutations = self.mutator.get_xss_mutations(base_payload)
                else:
                    mutations = self.mutator.get_sqli_mutations(base_payload)

                for payload in mutations:

                    # 아직 취약점 없는 키만 대상
                    pending_keys = [k for k in all_keys if k not in found_keys]
                    if not pending_keys:
                        break

                    # 페이로드 하나를 모든 pending 키에 동시에 주입
                    future_to_key: dict[Future, str] = {
                        executor.submit(
                            self._probe_one,
                            url, params, method, source,
                            payload, attack_type, key,
                        ): key
                        for key in pending_keys
                    }

                    for future in as_completed(future_to_key):
                        key = future_to_key[future]
                        try:
                            result = future.result()
                        except Exception:
                            continue
                        if result is not None:
                            results.append(result)
                            found_keys.add(key)   # 이 키는 이후 페이로드에서 스킵

        return results

    def _probe_one(
        self,
        url:         str,
        params:      dict,
        method:      str,
        source:      str,
        payload:     str,
        attack_type: str,
        key:         str,
    ) -> Optional[VulnResult]:
        """
        페이로드 하나를 단일 키에 주입하고 결과를 반환한다.
        취약 → VulnResult, 아니면 None.
        """
        # module을 스레드마다 독립 생성 → 공유 상태 충돌 방지
        if attack_type == "xss":
            from scanner.modules.xss import XSSModule
            module = XSSModule()
        else:
            from scanner.modules.sqli import SQLiModule
            module = SQLiModule()

        client        = HttpClient()
        attack_params = self.mutator.generate_attack_params(params, key, payload)
        try:
            response, elapsed = client.request(method, url, attack_params)
        except Exception as e:
            print(f"[PROBE EXCEPTION] key={key} | {type(e).__name__}: {e}")
            return None

        # ── 디버그 시작 ──
        #print(f"\n[PROBE] key={key} | payload={payload[:40]!r}")
        #print(f"        response={'None' if response is None else response.status_code} | elapsed={elapsed:.2f}s")
        #if response is not None:
        #    print(f"        body[:200]={response.text[:200]!r}")
        # ── 디버그 끝 ──

        if response is None:
            return None

        result = module.analyze(
            response  = response,
            elapsed   = elapsed,
            url       = url,
            parameter = key,
            payload   = payload,
            source    = source,
        )

        print(f"        severity={result.severity} | vulnerable={result.is_vulnerable()} | evidence={result.evidence!r}")

        return result if result.is_vulnerable() else None