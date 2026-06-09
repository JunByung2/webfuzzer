"""
payloads 테이블 통계 업데이트 전담 파일
- 스캔 완료 후 사용된 페이로드의 통계를 갱신
- 성공/실패 여부에 따라 업데이트 항목이 다름
"""
import json
import mysql.connector
from datetime import datetime
from config.config import DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD


def _conn():
    """
    MySQL 연결 객체 반환
    매 함수 호출마다 새 연결을 맺고, 작업 후 닫는 단순 구조
    """
    return mysql.connector.connect(
        host=DB_HOST,
        port=DB_PORT,
        database=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD,
        charset="utf8mb4"    # 한글/특수문자 페이로드 깨짐 방지
    )


def update_payload_stats(vuln_results):
    """
    스캔 완료 후 app.py에서 호출.
    injector.py가 반환한 vuln_results 리스트를 순회하며
    payloads 테이블의 통계 컬럼들을 갱신한다.

    성공/실패 상관없이 무조건 갱신:
        hit_count, success_rate, confidence_score, context_stats

    성공했을 때만 추가 갱신:
        success_count, last_success_at
    """
    # 결과가 없으면 DB 연결 자체를 하지 않음 (불필요한 커넥션 방지)
    if not vuln_results:
        return

    conn = _conn()
    # dictionary=True → 컬럼명을 키로 가지는 dict로 반환
    # ex) row["hit_count"], row["success_count"] 형태로 접근 가능
    cur  = conn.cursor(dictionary=True)

    for r in vuln_results:

        # ── 1) raw값으로 페이로드 조회 ──────────────────────────────
        # payloads 테이블에 미리 등록된 페이로드인지 확인
        # 등록되지 않은 페이로드(mutator가 변형한 파생 페이로드 등)는 스킵
        cur.execute("SELECT * FROM payloads WHERE raw = %s", (r.payload,))
        row = cur.fetchone()
        cur.fetchall()  

        if not row:
            continue

        # SAFE가 아니면 취약점 탐지 성공으로 판정
        is_success  = r.severity.value != "SAFE"

        # hit_count: 기존 값 +1 (이번 스캔에서 사용됐으므로)
        new_hit     = row["hit_count"] + 1

        # success_count: 성공했을 때만 +1, 실패면 기존 값 유지
        new_success = row["success_count"] + (1 if is_success else 0)

        # ── 2) success_rate 재계산 ───────────────────────────────────
        # 성공 횟수 / 전체 시도 횟수
        new_success_rate = new_success / new_hit

        # ── 3) confidence_score 갱신 ─────────────────────────────────
        # 시도 횟수가 적으면 신뢰도에 패널티 적용
        # ex) 1번 시도해서 1번 성공 → 성공률 100%지만 신뢰도는 10%
        #     10번 시도해서 10번 성공 → 성공률 100%, 신뢰도도 100%
        # 10번 이상 시도해야 신뢰도가 100% 반영됨
        trial_weight   = min(new_hit / 10.0, 1.0)
        new_confidence = new_success_rate * trial_weight

        # ── 4) context_stats JSON 갱신 ───────────────────────────────
        # 기존 JSON 불러오기 (없으면 빈 구조로 초기화)
        # context_stats는 어떤 상황에서 잘 먹혔는지 기록하는 세부 통계
        ctx = row["context_stats"] or {
            "by_param_name": {},   # 파라미터명별 통계 ex) {"id": {"success": 5, "fail": 2}}
            "by_param_type": {},   # 파라미터 타입별 통계 ex) {"numeric": {...}, "string": {...}}
            "by_method":     {}    # 요청 방식별 통계 ex) {"GET": {...}, "POST": {...}}
        }
        # DB에서 꺼낸 JSON이 문자열이면 dict로 변환
        if isinstance(ctx, str):
            ctx = json.loads(ctx)

        # by_param_name 갱신
        # 어떤 파라미터명에서 성공/실패했는지 기록
        # ex) searchTerm 파라미터에서 성공 → {"searchTerm": {"success": 1, "fail": 0}}
        param = r.parameter or "unknown"
        if param not in ctx["by_param_name"]:
            ctx["by_param_name"][param] = {"success": 0, "fail": 0}
        if is_success:
            ctx["by_param_name"][param]["success"] += 1
        else:
            ctx["by_param_name"][param]["fail"] += 1

        # by_param_type 갱신
        # 파라미터 값이 숫자면 numeric, 아니면 string으로 분류
        # ex) id=1 → numeric, q=hello → string
        param_type = "numeric" if str(r.payload).isdigit() else "string"
        if param_type not in ctx["by_param_type"]:
            ctx["by_param_type"][param_type] = {"success": 0, "fail": 0}
        if is_success:
            ctx["by_param_type"][param_type]["success"] += 1
        else:
            ctx["by_param_type"][param_type]["fail"] += 1

        # by_method 갱신
        # GET/POST 등 요청 방식별로 성공/실패 기록
        # r.source가 "form"/"query"로 오므로 대문자로 변환해서 저장
        method = getattr(r, "source", "GET").upper()
        if method not in ctx["by_method"]:
            ctx["by_method"][method] = {"success": 0, "fail": 0}
        if is_success:
            ctx["by_method"][method]["success"] += 1
        else:
            ctx["by_method"][method]["fail"] += 1

        # ── 5) UPDATE 쿼리 실행 ──────────────────────────────────────
        if is_success:
            # 성공했을 때 — last_success_at도 현재 시각으로 갱신
            cur.execute("""
                UPDATE payloads SET
                    hit_count        = %s,
                    success_count    = %s,
                    success_rate     = %s,
                    confidence_score = %s,
                    context_stats    = %s,
                    last_success_at  = %s
                WHERE raw = %s
            """, (
                new_hit,
                new_success,
                new_success_rate,
                new_confidence,
                json.dumps(ctx),       # dict → JSON 문자열로 변환해서 저장
                datetime.utcnow(),     # 현재 시각 (UTC 기준)
                r.payload
            ))
        else:
            # 실패했을 때 — last_success_at은 건드리지 않음
            cur.execute("""
                UPDATE payloads SET
                    hit_count        = %s,
                    success_count    = %s,
                    success_rate     = %s,
                    confidence_score = %s,
                    context_stats    = %s
                WHERE raw = %s
            """, (
                new_hit,
                new_success,
                new_success_rate,
                new_confidence,
                json.dumps(ctx),
                r.payload
            ))

    conn.commit()       # 모든 UPDATE를 한 번에 커밋
    cur.close()
    conn.close()        # 커넥션 반납