"use client";
import React from "react";

export default function GuidePage() {
  const hoverClasses =
    "transition-all duration-300 transform hover:scale-105 hover:shadow-2xl cursor-default";

  const containerStyle = {
    maxWidth: "1400px",
    margin: "0 auto",
    padding: "40px 40px",
    display: "flex",
    gap: "40px",
    justifyContent: "center",
    flexWrap: "wrap",
  } as const;

  const boxStyle = {
    flex: "1",
    minWidth: "500px",
    minHeight: "600px",
    padding: "3rem",
    border: "2px solid #f3f4f6",
    borderRadius: "40px",
    background: "white",
    boxShadow: "0 4px 6px -1px rgba(0, 0, 0, 0.1)",
    display: "flex",
    flexDirection: "column",
    alignItems: "flex-start",
  } as const;

  const titleStyle = {
    fontSize: "24px",
    fontWeight: "bold",
    marginBottom: "16px",
    color: "#111827",
  } as const;

  const lineStyle = {
    width: "100%",
    height: "1px",
    backgroundColor: "#000",
    marginBottom: "24px",
  } as const;

  const listStyle = {
    listStyleType: "disc",
    paddingLeft: "20px",
    lineHeight: "2",
    color: "#4b5563",
    fontSize: "16px",
  } as const;

  const subTitleStyle = {
    fontSize: "15px",
    fontWeight: "bold",
    color: "#1e3a5f",
    marginTop: "16px",
    marginBottom: "4px",
  } as const;

  return (
    <div style={{ minHeight: "100vh", padding: "40px 0" }}>
      <main style={containerStyle}>
        {/* 왼쪽: 스캐너 사용 방법 */}
        <section style={boxStyle} className={hoverClasses}>
          <h2 style={titleStyle}>스캐너 사용 방법</h2>
          <div style={lineStyle}></div>
          <ul style={listStyle}>
            <li>
              <p style={subTitleStyle}>URL 입력</p>
              스캔할 웹사이트 주소를 입력창에 입력합니다. http:// 또는
              https://로 시작하는 전체 URL을 입력하거나, 도메인만 입력해도
              자동으로 처리됩니다.
            </li>
            <li>
              <p style={subTitleStyle}>스캔 시작</p>
              '분석 시작' 버튼을 클릭하면 자동으로 크롤링 → 취약점 스캔 → AI
              분석 순서로 진행됩니다. 진행 상황은 상단 프로그레스 바에서
              실시간으로 확인할 수 있습니다.
            </li>
            <li>
              <p style={subTitleStyle}>결과 확인</p>
              스캔이 완료되면 탐지된 취약점 목록이 왼쪽 패널에 표시됩니다.
              항목을 클릭하면 오른쪽에서 위험 등급, 사용된 페이로드, 탐지 근거
              등 세부 정보를 확인할 수 있습니다.
            </li>
            <li>
              <p style={subTitleStyle}>상세 리포트 보기</p>
              스캔 완료 후 '상세 결과 보기' 버튼을 클릭하면 취약점 설명, 실제
              피해 가능성, 대응방안이 포함된 전체 리포트 페이지로 이동합니다.
            </li>
            <li>
              <p style={subTitleStyle}>PDF 다운로드</p>
              상세 리포트 페이지 우측 상단의 'PDF 다운로드' 버튼으로 전체 스캔
              결과를 PDF 파일로 저장할 수 있습니다.
            </li>
          </ul>
        </section>

        {/* 오른쪽: 취약점 대응 가이드 */}
        <section style={boxStyle} className={hoverClasses}>
          <h2 style={titleStyle}>취약점 대응 가이드</h2>
          <div style={lineStyle}></div>
          <ul style={listStyle}>
            <li>
              <p style={subTitleStyle}>XSS (Cross-Site Scripting) 대응</p>
              모든 사용자 입력값에 HTML 엔티티 인코딩을 적용하고,
              Content-Security-Policy(CSP) 헤더를 설정하여 인라인 스크립트를
              차단합니다. DOM 조작 시 innerHTML 대신 textContent를 사용하는 것을
              권장합니다.
            </li>
            <li>
              <p style={subTitleStyle}>SQL Injection 대응</p>
              Prepared Statement(파라미터화 쿼리)를 사용하여 SQL Injection을
              원천 차단합니다. ORM 프레임워크를 활용하고, DB 계정에는 최소
              권한만 부여합니다. 에러 메시지는 사용자에게 노출하지 않고 로그에만
              기록합니다.
            </li>
            <li>
              <p style={subTitleStyle}>위험도 등급 이해</p>
              탐지된 취약점은 CRITICAL / HIGH / MEDIUM / LOW 4단계로 분류됩니다.
              CRITICAL과 HIGH 등급은 즉시 조치가 필요하며, MEDIUM과 LOW는 정기
              점검 주기에 맞춰 처리하는 것을 권장합니다.
            </li>
            <li>
              <p style={subTitleStyle}>보안 패치 적용</p>
              취약점 발견 후 해당 파라미터 또는 엔드포인트에 대한 입력값 검증
              로직을 추가하고, 프레임워크 및 라이브러리를 최신 버전으로
              유지합니다.
            </li>
            <li>
              <p style={subTitleStyle}>정기 점검 권고</p>
              서비스 배포 전과 주요 기능 변경 후에는 반드시 스캔을 실행하고, 월
              1회 이상 정기적인 보안 점검을 수행할 것을 권장합니다.
            </li>
          </ul>
        </section>
      </main>
    </div>
  );
}
