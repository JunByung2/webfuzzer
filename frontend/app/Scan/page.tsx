"use client";

import React, { useState, useEffect, useRef, useCallback } from "react";
import { Search, FileText } from "lucide-react";
import { useRouter } from "next/navigation";
import { Prism as SyntaxHighlighter } from "react-syntax-highlighter";
import { oneDark } from "react-syntax-highlighter/dist/esm/styles/prism";

const BACKEND_URL =
  process.env.NEXT_PUBLIC_BACKEND_URL ?? "http://localhost:5000";

const TEST_SITES = [
  { name: "Zero Bank", url: "http://zero.webappsecurity.com" },
  { name: "Altoro Mutual", url: "http://demo.testfire.net" },
  { name: "Vulnweb", url: "http://testphp.vulnweb.com" },
];

// ------------------------------------------------------------------ //
//  타입 — VulnResult.to_dict() 구조에 맞춤                            //
// ------------------------------------------------------------------ //

interface VulnerabilityItem {
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "SAFE";
  vuln_type: "xss" | "sqli" | "none";
  evidence: string;
  url: string;
  parameter: string;
  payload: string;
  reflection: string;
  source: "query" | "form" | "";
  scanned_at: string;
}

interface AiVulnerability {
  id: number;
  vuln_type: string;
  severity: string;
  cvss: number;
  name: string;
  url: string;
  parameter: string;
  payload: string;
  source: string;
  reflection: string;
  description: string;
  evidence: string;
  impact: string;
  remediation: string[];
}

interface ScanStatus {
  status: "running" | "success" | "error";
  progress: number;
  phase: string;
  message: string;
  page_count?: number;
  vuln_count?: number;
  vuln_results?: VulnerabilityItem[];
  ai_analysis?: {
    summary: Record<string, unknown>;
    vulnerabilities: AiVulnerability[];
  };
}

type ScanStep =
  | "idle"
  | "starting"
  | "crawling"
  | "scanning"
  | "ai_analysis"
  | "done";

const PHASE_MAP: Record<string, ScanStep> = {
  starting: "starting",
  crawling: "crawling",
  scanning: "scanning",
  ai_analysis: "ai_analysis",
};

const STEP_LABELS: Record<ScanStep, string> = {
  idle: "대기",
  starting: "준비 중",
  crawling: "크롤링",
  scanning: "스캔",
  ai_analysis: "AI 분석",
  done: "완료",
};

// ------------------------------------------------------------------ //
//  severity → UI 스타일 매핑                                           //
// ------------------------------------------------------------------ //

const SEVERITY_META: Record<
  string,
  {
    label: string;
    bg: string;
    text: string;
    border: string;
  }
> = {
  CRITICAL: {
    label: "Critical",
    bg: "bg-red-100",
    text: "text-red-700",
    border: "border-red-400",
  },
  HIGH: {
    label: "High",
    bg: "bg-orange-100",
    text: "text-orange-700",
    border: "border-orange-400",
  },
  MEDIUM: {
    label: "Medium",
    bg: "bg-yellow-100",
    text: "text-yellow-700",
    border: "border-yellow-400",
  },
  LOW: {
    label: "Low",
    bg: "bg-green-100",
    text: "text-green-700",
    border: "border-green-400",
  },
  SAFE: {
    label: "Safe",
    bg: "bg-gray-100",
    text: "text-gray-500",
    border: "border-gray-300",
  },
};

const VULN_TYPE_LABEL: Record<string, string> = {
  xss: "XSS",
  sqli: "SQL Injection",
  none: "-",
};

// severity → CVSS 점수 (표시용)
const SEVERITY_SCORE: Record<string, number> = {
  CRITICAL: 9.5,
  HIGH: 7.5,
  MEDIUM: 5.0,
  LOW: 2.0,
  SAFE: 0.0,
};

// ------------------------------------------------------------------ //
//  컴포넌트                                                             //
// ------------------------------------------------------------------ //

const ScanPage = () => {
  const router = useRouter();
  const [url, setUrl] = useState("");
  const [isMounted, setIsMounted] = useState(false);
  const [isScanning, setIsScanning] = useState(false);
  const [scanStep, setScanStep] = useState<ScanStep>("idle");
  const [progress, setProgress] = useState(0);
  const [statusMessage, setStatusMessage] = useState("");
  const [scanResults, setScanResults] = useState<VulnerabilityItem[]>([]);
  const [selected, setSelected] = useState<VulnerabilityItem | null>(null);
  const [aiAnalysis, setAiAnalysis] = useState<
    ScanStatus["ai_analysis"] | null
  >(null);

  const pollingRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const stopPolling = useCallback(() => {
    if (pollingRef.current) {
      clearInterval(pollingRef.current);
      pollingRef.current = null;
    }
  }, []);

  useEffect(() => {
    setIsMounted(true);
    return () => stopPolling();
  }, [stopPolling]);

  if (!isMounted) return <div className="min-h-screen" />;

  const handleError = (msg: string) => {
    stopPolling();
    setStatusMessage(msg);
    setIsScanning(false);
    setScanStep("idle");
  };

  const startPolling = (targetUrl: string) => {
    stopPolling();

    pollingRef.current = setInterval(async () => {
      try {
        const res = await fetch(
          `${BACKEND_URL}/scan/status?url=${encodeURIComponent(targetUrl)}`,
        );

        if (res.status === 404) {
          handleError("스캔 상태를 찾을 수 없습니다.");
          return;
        }
        if (!res.ok) throw new Error(`상태 조회 실패 (${res.status})`);

        const data: ScanStatus = await res.json();

        setProgress(data.progress ?? 0);
        setStatusMessage(data.message ?? "");
        if (data.phase && PHASE_MAP[data.phase]) {
          setScanStep(PHASE_MAP[data.phase]);
        }

        if (data.status === "success") {
          stopPolling();
          setProgress(100);
          setScanStep("done");
          setIsScanning(false);
          setStatusMessage(
            `완료! ${data.page_count ?? 0}개 페이지 · 취약점 ${data.vuln_count ?? 0}건`,
          );
          // vuln_results 키로 변경
          if (Array.isArray(data.vuln_results)) {
            setScanResults(data.vuln_results);
          }
          if (data.ai_analysis) {
            setAiAnalysis(data.ai_analysis);
          }
        }

        if (data.status === "error") {
          handleError(`스캔 오류: ${data.message}`);
        }
      } catch {
        handleError("서버 연결이 끊겼습니다.");
      }
    }, 1000);
  };

  const handleScan = async (forcedUrl?: string) => {
    const targetInput = forcedUrl || url;
    if (!targetInput.trim() || isScanning) return;

    const targetUrl = targetInput.startsWith("http")
      ? targetInput.trim()
      : `https://${targetInput.trim()}`;

    if (forcedUrl) setUrl(targetUrl);
    setIsScanning(true);
    setScanStep("starting");
    setProgress(0);
    setStatusMessage("스캔 준비 중...");
    setScanResults([]);
    setSelected(null);
    setAiAnalysis(null);

    try {
      const res = await fetch(`${BACKEND_URL}/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: targetUrl }),
      });

      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error((errData as any).error ?? `서버 오류 (${res.status})`);
      }

      startPolling(targetUrl);
    } catch (err) {
      handleError(
        `연결 실패: ${err instanceof Error ? err.message : "알 수 없는 오류"}`,
      );
    }
  };

  const steps: ScanStep[] = [
    "starting",
    "crawling",
    "scanning",
    "ai_analysis",
    "done",
  ];
  const currentStepIndex = steps.indexOf(scanStep);

  return (
    <div className="min-h-screen p-8 max-w-7xl mx-auto font-sans text-gray-800">
      {/* 스캔 입력 + 진행 상태 */}
      <section className="mb-10 text-center">
        <h2 className="text-2xl font-bold mb-6 text-slate-900">
          AI 기반 웹 취약점 자동 탐지
        </h2>

        <div className="flex justify-center items-center gap-4">
          <div className="relative w-1/2">
            <input
              type="text"
              placeholder="URL을 입력하세요 (예: example.com)"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleScan()}
              className="w-full p-3 pl-10 border-2 border-gray-300 rounded-md focus:outline-none focus:border-slate-500 text-black bg-white shadow-sm"
            />
            <Search
              className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400"
              size={16}
            />
          </div>
          <button
            onClick={() => handleScan()}
            disabled={isScanning}
            className={`px-10 py-3 rounded-md font-bold text-white transition-all active:scale-95 shadow-md ${
              isScanning
                ? "bg-slate-400 cursor-not-allowed"
                : "bg-slate-700 hover:bg-slate-900 border-2 border-slate-800"
            }`}
          >
            {isScanning ? "분석 중..." : "분석 시작"}
          </button>
        </div>

        {/* 테스트 샘플 버튼 */}
        <div className="mt-4 flex justify-center items-center gap-3">
          <span className="text-xs font-bold text-gray-400">테스트 샘플:</span>
          {TEST_SITES.map((site) => (
            <button
              key={site.url}
              onClick={() => handleScan(site.url)}
              disabled={isScanning}
              className="text-xs px-3 py-1.5 border border-gray-300 rounded-full hover:bg-gray-100 hover:border-gray-400 transition-colors text-gray-600 font-medium disabled:opacity-50"
            >
              {site.name}
            </button>
          ))}
        </div>

        {scanStep !== "idle" && (
          <div className="mt-8 max-w-2xl mx-auto">
            <div className="flex justify-between mb-3">
              {steps.map((step, i) => (
                <span
                  key={step}
                  className={`text-[11px] px-2 py-0.5 rounded-full font-bold transition-colors ${
                    i < currentStepIndex
                      ? "bg-blue-100 text-blue-600"
                      : i === currentStepIndex
                        ? "bg-blue-500 text-white animate-pulse"
                        : "bg-gray-100 text-gray-400"
                  }`}
                >
                  {STEP_LABELS[step]}
                </span>
              ))}
            </div>

            <div className="w-full bg-gray-200 h-2.5 rounded-full overflow-hidden shadow-inner">
              <div
                className="bg-blue-500 h-full transition-all duration-500"
                style={{ width: `${progress}%` }}
              />
            </div>

            <div className="flex justify-between items-center mt-2">
              <span className="text-xs text-gray-500">{statusMessage}</span>
              <span className="text-xs font-bold text-blue-500">
                {progress.toFixed(1)}%
              </span>
            </div>
          </div>
        )}
      </section>

      {/* 스캔 완료 후 상세 결과 버튼 */}
      {scanStep === "done" && (
        <div className="flex justify-center mb-6">
          <button
            onClick={() => {
              sessionStorage.setItem(
                "scanResults",
                JSON.stringify({
                  url,
                  results: scanResults,
                  ai_analysis: aiAnalysis,
                }),
              );
              router.push("/Result");
            }}
            className="flex items-center gap-2 px-6 py-3 bg-blue-600 hover:bg-blue-700 text-white font-bold rounded-lg shadow-md transition-all active:scale-95"
          >
            <FileText size={18} />
            상세 결과 보기
          </button>
        </div>
      )}

      <div className="grid grid-cols-12 gap-6">
        {/* 취약점 목록 */}
        <aside className="col-span-4 border-2 border-gray-300 rounded-lg overflow-hidden bg-white text-black shadow-sm">
          <div className="bg-gray-100 p-3 border-b-2 border-gray-300 font-bold text-lg flex justify-between items-center">
            <span>탐지된 취약점</span>
            {scanResults.length > 0 && (
              <span className="text-xs font-normal text-gray-500">
                {scanResults.length}건
              </span>
            )}
          </div>

          <div style={{ height: "500px" }} className="overflow-y-auto">
            {scanStep === "done" && scanResults.length === 0 && (
              <div className="p-6 text-center text-sm text-gray-400 italic">
                탐지된 취약점이 없습니다.
              </div>
            )}

            {scanResults.map((item, i) => {
              const meta = SEVERITY_META[item.severity] ?? SEVERITY_META.SAFE;
              return (
                <div
                  key={i}
                  onClick={() => setSelected(item)}
                  className={`p-4 border-b border-gray-100 cursor-pointer transition-colors ${
                    selected === item
                      ? "bg-blue-50"
                      : "bg-white hover:bg-gray-50"
                  }`}
                >
                  <div className="flex justify-between items-center">
                    <div className="flex flex-col overflow-hidden gap-0.5">
                      {/* 취약점 종류 + 파라미터 */}
                      <span className="font-bold text-sm truncate">
                        {VULN_TYPE_LABEL[item.vuln_type]} —{" "}
                        {item.parameter || "-"}
                      </span>
                      {/* URL (짧게) */}
                      <span className="text-[10px] text-gray-400 truncate">
                        {item.url}
                      </span>
                    </div>
                    <span
                      className={`text-[10px] px-2 py-1 rounded border font-bold shrink-0 ml-2 ${meta.bg} ${meta.text} ${meta.border}`}
                    >
                      {meta.label}
                    </span>
                  </div>
                </div>
              );
            })}
          </div>
        </aside>

        {/* 상세 정보 */}
        <main className="col-span-8 border-2 border-gray-300 rounded-lg p-6 bg-white text-black shadow-sm">
          <h3 className="text-xl font-bold mb-6 flex items-center gap-2">
            세부 정보
            <span className="text-sm text-gray-400 font-normal">
              | 취약점 리포트
            </span>
          </h3>

          <div className="grid grid-cols-2 gap-6 mb-8">
            {/* 위험 등급 */}
            <div className="border-2 border-gray-200 p-4 rounded-md text-center">
              <h4 className="font-bold mb-3 text-sm text-gray-600">
                위험 등급
              </h4>
              <div className="flex flex-col items-center justify-center p-8 border-2 border-dashed border-gray-200 rounded-lg bg-gray-50">
                {selected ? (
                  <>
                    <div
                      className={`px-6 py-2 border-2 rounded font-bold text-lg
                      ${SEVERITY_META[selected.severity]?.bg}
                      ${SEVERITY_META[selected.severity]?.text}
                      ${SEVERITY_META[selected.severity]?.border}`}
                    >
                      {SEVERITY_META[selected.severity]?.label}
                    </div>
                    <span className="text-sm font-bold mt-2">
                      CVSS {SEVERITY_SCORE[selected.severity]} 점
                    </span>
                    <span className="text-xs text-gray-400 mt-1">
                      {VULN_TYPE_LABEL[selected.vuln_type]}
                    </span>
                  </>
                ) : (
                  <span className="text-gray-400 text-sm italic">
                    항목을 선택하세요
                  </span>
                )}
              </div>
            </div>

            {/* 탐지 정보 */}
            <div className="border-2 border-gray-200 p-4 rounded-md">
              <h4 className="font-bold mb-3 text-sm text-gray-600">
                탐지 정보
              </h4>
              <div className="bg-gray-50 p-4 rounded border border-gray-100 text-sm text-gray-600 space-y-2">
                {selected ? (
                  <>
                    <div>
                      <span className="font-bold text-gray-400 text-xs">
                        증거
                      </span>
                      <p>{selected.evidence}</p>
                    </div>
                    <div>
                      <span className="font-bold text-gray-400 text-xs">
                        파라미터
                      </span>
                      <p>{selected.parameter || "-"}</p>
                    </div>
                    <div>
                      <span className="font-bold text-gray-400 text-xs">
                        출처
                      </span>
                      <p>{selected.source || "-"}</p>
                    </div>
                    <div>
                      <span className="font-bold text-gray-400 text-xs">
                        반사 방식
                      </span>
                      <p>{selected.reflection || "-"}</p>
                    </div>
                    <div>
                      <span className="font-bold text-gray-400 text-xs">
                        스캔 시각
                      </span>
                      <p>
                        {selected.scanned_at
                          ? new Date(selected.scanned_at).toLocaleString(
                              "ko-KR",
                            )
                          : "-"}
                      </p>
                    </div>
                  </>
                ) : (
                  <span className="italic text-gray-400">
                    탐지 정보가 여기에 표시됩니다.
                  </span>
                )}
              </div>
            </div>
          </div>

          {/* 페이로드 / URL */}
          <div className="grid grid-cols-2 gap-4">
            <div>
              <h4 className="font-bold text-xs mb-2 text-gray-500">
                사용된 페이로드
              </h4>
              <div
                style={{ height: "250px" }}
                className="bg-slate-900 border border-slate-700 rounded overflow-hidden text-[11px]"
              >
                <SyntaxHighlighter
                  language="html"
                  style={oneDark}
                  showLineNumbers
                  customStyle={{
                    background: "transparent",
                    height: "100%",
                    margin: 0,
                  }}
                >
                  {selected?.payload || "// 페이로드 없음"}
                </SyntaxHighlighter>
              </div>
            </div>

            <div>
              <h4 className="font-bold text-xs mb-2 text-gray-500">
                취약한 URL
              </h4>
              <div
                style={{ height: "250px" }}
                className="bg-slate-900 border border-slate-700 rounded overflow-hidden text-[11px]"
              >
                <SyntaxHighlighter
                  language="http"
                  style={oneDark}
                  showLineNumbers
                  customStyle={{
                    background: "transparent",
                    height: "100%",
                    margin: 0,
                  }}
                >
                  {selected?.url || "// URL 없음"}
                </SyntaxHighlighter>
              </div>
            </div>
          </div>
        </main>
      </div>
    </div>
  );
};

export default ScanPage;
