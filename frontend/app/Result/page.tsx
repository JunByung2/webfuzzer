"use client";

import React, { useState, useEffect, useRef } from "react";
import { useRouter } from "next/navigation";
import { PDFDocument, rgb } from "pdf-lib";
import fontkit from "@pdf-lib/fontkit";
import {
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
} from "recharts";
import {
  ArrowLeft,
  Download,
  ShieldAlert,
  Globe,
  Tag,
  Clock,
  Bot,
  MessageCircle,
  X,
  Send,
} from "lucide-react";

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

const SEVERITY_META: Record<
  string,
  { label: string; bg: string; text: string; border: string; color: string }
> = {
  CRITICAL: {
    label: "Critical",
    bg: "bg-red-100",
    text: "text-red-700",
    border: "border-red-400",
    color: "#ef4444",
  },
  HIGH: {
    label: "High",
    bg: "bg-orange-100",
    text: "text-orange-700",
    border: "border-orange-400",
    color: "#f97316",
  },
  MEDIUM: {
    label: "Medium",
    bg: "bg-yellow-100",
    text: "text-yellow-700",
    border: "border-yellow-400",
    color: "#eab308",
  },
  LOW: {
    label: "Low",
    bg: "bg-green-100",
    text: "text-green-700",
    border: "border-green-400",
    color: "#22c55e",
  },
  SAFE: {
    label: "Safe",
    bg: "bg-gray-100",
    text: "text-gray-500",
    border: "border-gray-300",
    color: "#9ca3af",
  },
};

const VULN_TYPE_LABEL: Record<string, string> = {
  xss: "XSS",
  sqli: "SQL Injection",
  none: "안전",
};
const SEVERITY_SCORE: Record<string, number> = {
  CRITICAL: 9.5,
  HIGH: 7.5,
  MEDIUM: 5.0,
  LOW: 2.0,
  SAFE: 0.0,
};

// ══════════════════════════════════════════════════════════════════
// 헬퍼: ai_description 문장 분리 렌더링
// ══════════════════════════════════════════════════════════════════

function AiDescriptionBlock({ text }: { text: string }) {
  if (!text) return <p className="text-xs text-gray-400 italic">분석 중...</p>;
  const sentences = text
    .split(/(?<=\.)\s+/)
    .map((s) => s.trim())
    .filter(Boolean);
  return (
    <div className="space-y-1.5">
      {sentences.map((s, i) => (
        <p key={i} className="text-xs text-indigo-900 leading-relaxed">
          {s}
        </p>
      ))}
    </div>
  );
}

// ══════════════════════════════════════════════════════════════════
// 헬퍼: reason 코드 블록 하이라이트
// ══════════════════════════════════════════════════════════════════

function ReasonText({ text }: { text: string }) {
  if (!text) return null;
  const lines = text.split(/\n/);
  const isCodeLine = (line: string) =>
    /^(import |cursor\.|conn\.|db\.|stmt\.|def |const |let |var |if |return |html\.|escape\(|execute\(|prepare\()/.test(
      line.trim(),
    );

  type Segment =
    | { type: "text"; content: string }
    | { type: "code"; lines: string[] };
  const segments: Segment[] = [];
  let buf: string[] = [];

  lines.forEach((line) => {
    if (isCodeLine(line)) {
      buf.push(line);
    } else {
      if (buf.length > 0) {
        segments.push({ type: "code", lines: buf });
        buf = [];
      }
      if (line.trim()) segments.push({ type: "text", content: line });
    }
  });
  if (buf.length > 0) segments.push({ type: "code", lines: buf });

  if (segments.every((s) => s.type === "text")) {
    return <p className="text-xs text-blue-800 leading-relaxed">{text}</p>;
  }

  return (
    <div className="space-y-1.5">
      {segments.map((seg, i) =>
        seg.type === "code" ? (
          <pre
            key={i}
            className="bg-slate-900 text-green-400 text-[11px] font-mono rounded-lg px-3 py-2 overflow-x-auto leading-relaxed"
          >
            {(seg as { type: "code"; lines: string[] }).lines.join("\n")}
          </pre>
        ) : (
          <p key={i} className="text-xs text-blue-800 leading-relaxed">
            {(seg as { type: "text"; content: string }).content}
          </p>
        ),
      )}
    </div>
  );
}

// ══════════════════════════════════════════════════════════════════
// 채팅 모달 컴포넌트
// ══════════════════════════════════════════════════════════════════

interface ChatContext {
  vuln_type: string;
  severity: string;
  url: string;
  parameter: string;
  payload: string;
  action: string;
  reason: string;
}

interface ChatMessage {
  role: "user" | "assistant";
  content: string;
}

function ChatModal({
  context,
  onClose,
  backendUrl,
}: {
  context: ChatContext;
  onClose: () => void;
  backendUrl: string;
}) {
  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      role: "assistant",
      content: `안녕하세요! **"${context.action}"** 대응방안에 대해 궁금한 점을 물어보세요.\n\n예를 들어:\n- "이 코드에 어떻게 적용하나요?"\n- "다른 방법은 없나요?"\n- "이 방법으로 완전히 막을 수 있나요?"`,
    },
  ]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const bottomRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  useEffect(() => {
    inputRef.current?.focus();
  }, []);

  const sendMessage = async () => {
    const text = input.trim();
    if (!text || loading) return;

    const userMsg: ChatMessage = { role: "user", content: text };
    const newMessages = [...messages, userMsg];
    setMessages(newMessages);
    setInput("");
    setLoading(true);

    try {
      const res = await fetch(`${backendUrl}/chat`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          messages: newMessages,
          context,
        }),
      });

      if (res.ok) {
        const data = await res.json();
        setMessages((prev) => [
          ...prev,
          { role: "assistant", content: data.reply },
        ]);
      } else {
        setMessages((prev) => [
          ...prev,
          {
            role: "assistant",
            content: "오류가 발생했습니다. 다시 시도해주세요.",
          },
        ]);
      }
    } catch {
      setMessages((prev) => [
        ...prev,
        { role: "assistant", content: "서버 연결에 실패했습니다." },
      ]);
    } finally {
      setLoading(false);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
  };

  // 마크다운 굵기 처리 (간단하게)
  const renderContent = (text: string) => {
    return text.split("\n").map((line, i) => {
      const parts = line.split(/\*\*(.*?)\*\*/g);
      return (
        <p key={i} className={line === "" ? "mt-1" : "leading-relaxed"}>
          {parts.map((part, j) =>
            j % 2 === 1 ? <strong key={j}>{part}</strong> : part,
          )}
        </p>
      );
    });
  };

  return (
    // 모달 오버레이
    <div className="fixed inset-0 z-50 flex items-center justify-center p-6">
      {/* 반투명 배경 */}
      <div
        className="absolute inset-0 bg-black bg-opacity-50"
        onClick={onClose}
      />

      {/* 채팅 패널 — result/page.tsx 와 동일한 white 카드 + slate 헤더 */}
      <div className="relative z-10 w-full max-w-lg h-[600px] bg-white rounded-2xl shadow-2xl flex flex-col overflow-hidden border border-gray-100">
        {/* 헤더 — bg-slate-800 (상세 분석 헤더와 동일) */}
        <div className="bg-slate-800 px-5 py-4 flex items-center gap-3 shrink-0">
          <div className="w-7 h-7 rounded-lg bg-slate-700 flex items-center justify-center shrink-0">
            <Bot size={15} className="text-slate-300" />
          </div>
          <div className="flex-1 min-w-0">
            <p className="text-white font-bold text-sm">대응방안 AI 상담</p>
            <p className="text-slate-400 text-[11px] truncate mt-0.5">
              {context.action}
            </p>
          </div>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-white hover:bg-slate-700 p-1.5 rounded-lg transition-colors"
          >
            <X size={16} />
          </button>
        </div>

        {/* 컨텍스트 배지 — bg-gray-50 (기본 정보 카드와 동일) */}
        <div className="bg-gray-50 border-b border-gray-100 px-5 py-2.5 flex gap-2 flex-wrap shrink-0">
          <span className="text-[10px] bg-white border border-gray-200 text-gray-600 px-2 py-0.5 rounded font-mono font-bold">
            {VULN_TYPE_LABEL[context.vuln_type] ?? context.vuln_type}
          </span>
          <span className="text-[10px] bg-white border border-gray-200 text-gray-600 px-2 py-0.5 rounded font-mono">
            {context.parameter}
          </span>
          <span
            className={`text-[10px] px-2 py-0.5 rounded border font-bold ${SEVERITY_META[context.severity]?.bg} ${SEVERITY_META[context.severity]?.text} ${SEVERITY_META[context.severity]?.border}`}
          >
            {SEVERITY_META[context.severity]?.label}
          </span>
        </div>

        {/* 메시지 목록 */}
        <div className="flex-1 overflow-y-auto px-5 py-4 space-y-4 bg-white">
          {messages.map((msg, i) => (
            <div
              key={i}
              className={`flex gap-2.5 ${msg.role === "user" ? "justify-end" : "justify-start"}`}
            >
              {/* AI 아이콘 — 취약점 상세 분석의 AI 배지 스타일 */}
              {msg.role === "assistant" && (
                <div className="w-6 h-6 rounded bg-slate-700 flex items-center justify-center shrink-0 mt-0.5">
                  <Bot size={12} className="text-slate-300" />
                </div>
              )}
              <div
                className={`max-w-[78%] px-3.5 py-2.5 text-xs leading-relaxed space-y-1 rounded-xl ${
                  msg.role === "user"
                    ? "bg-slate-800 text-white rounded-tr-sm"
                    : "bg-gray-100 text-gray-800 rounded-tl-sm border border-gray-200"
                }`}
              >
                {renderContent(msg.content)}
              </div>
              {/* 사용자 아이콘 자리 (정렬용) */}
              {msg.role === "user" && <div className="w-6 shrink-0" />}
            </div>
          ))}

          {/* 로딩 */}
          {loading && (
            <div className="flex gap-2.5 justify-start">
              <div className="w-6 h-6 rounded bg-slate-700 flex items-center justify-center shrink-0 mt-0.5">
                <Bot size={12} className="text-slate-300" />
              </div>
              <div className="bg-gray-100 border border-gray-200 px-4 py-3 rounded-xl rounded-tl-sm">
                <div className="flex gap-1 items-center h-4">
                  <span
                    className="w-1.5 h-1.5 bg-slate-400 rounded-full animate-bounce"
                    style={{ animationDelay: "0ms" }}
                  />
                  <span
                    className="w-1.5 h-1.5 bg-slate-400 rounded-full animate-bounce"
                    style={{ animationDelay: "150ms" }}
                  />
                  <span
                    className="w-1.5 h-1.5 bg-slate-400 rounded-full animate-bounce"
                    style={{ animationDelay: "300ms" }}
                  />
                </div>
              </div>
            </div>
          )}
          <div ref={bottomRef} />
        </div>

        {/* 입력창 — 카드 하단과 동일한 border-t */}
        <div className="border-t border-gray-100 px-4 py-3 flex gap-2 items-end shrink-0 bg-white">
          <textarea
            ref={inputRef}
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="궁금한 점을 입력하세요  (Enter 전송 · Shift+Enter 줄바꿈)"
            rows={2}
            className="flex-1 resize-none border border-gray-200 rounded-lg text-xs px-3 py-2 focus:outline-none focus:border-slate-400 text-gray-800 leading-relaxed bg-gray-50"
          />
          <button
            onClick={sendMessage}
            disabled={!input.trim() || loading}
            className={`p-2.5 rounded-lg transition-all active:scale-95 shrink-0 ${
              !input.trim() || loading
                ? "bg-gray-100 text-gray-300 cursor-not-allowed"
                : "bg-slate-800 text-white hover:bg-slate-900 shadow-sm"
            }`}
          >
            <Send size={15} />
          </button>
        </div>
      </div>
    </div>
  );
}

// ══════════════════════════════════════════════════════════════════
// 메인 ResultPage
// ══════════════════════════════════════════════════════════════════

export default function ResultPage() {
  const router = useRouter();
  const reportRef = useRef<HTMLDivElement>(null);

  const [scannedUrl, setScannedUrl] = useState("");
  const [results, setResults] = useState<VulnerabilityItem[]>([]);
  const [selected, setSelected] = useState<VulnerabilityItem | null>(null);
  const [isDownloading, setIsDownloading] = useState(false);
  const [isMounted, setIsMounted] = useState(false);
  const [vulnInfo, setVulnInfo] = useState<{
    name?: string;
    description?: string;
    impact?: string[];
    remediation?: any[];
    evidence?: string;
    ai_description?: string;
  } | null>(null);
  const [vulnInfoLoading, setVulnInfoLoading] = useState(false);

  // 채팅 모달 상태
  const [chatContext, setChatContext] = useState<ChatContext | null>(null);

  const BACKEND_URL =
    process.env.NEXT_PUBLIC_BACKEND_URL ?? "http://localhost:5000";

  const fetchVulnInfo = async (item: VulnerabilityItem) => {
    if (item.vuln_type === "none") {
      setVulnInfo(null);
      return;
    }
    setVulnInfoLoading(true);
    try {
      const res = await fetch(`${BACKEND_URL}/vuln-info/by-result`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          vuln_type: item.vuln_type,
          severity: item.severity,
          url: item.url,
          parameter: item.parameter,
          payload: item.payload,
          evidence: item.evidence,
          source: item.source,
          reflection: item.reflection,
        }),
      });
      if (res.ok) setVulnInfo(await res.json());
    } catch {
      setVulnInfo(null);
    } finally {
      setVulnInfoLoading(false);
    }
  };

  useEffect(() => {
    setIsMounted(true);
    try {
      const raw = sessionStorage.getItem("scanResults");
      if (raw) {
        const parsed = JSON.parse(raw);
        setScannedUrl(parsed.url ?? "");
        setResults(parsed.results ?? []);
        if (parsed.results?.length > 0) {
          setSelected(parsed.results[0]);
          fetchVulnInfo(parsed.results[0]);
        }
      }
    } catch {}
  }, []);

  if (!isMounted) return <div className="min-h-screen" />;

  const severityCounts = results.reduce<Record<string, number>>((acc, r) => {
    acc[r.severity] = (acc[r.severity] ?? 0) + 1;
    return acc;
  }, {});

  const pieData = Object.entries(severityCounts)
    .filter(([, v]) => v > 0)
    .map(([key, value]) => ({
      name: SEVERITY_META[key]?.label ?? key,
      value,
      color: SEVERITY_META[key]?.color ?? "#9ca3af",
    }));

  const vulnTypeCounts = results.reduce<Record<string, number>>((acc, r) => {
    const label = VULN_TYPE_LABEL[r.vuln_type] ?? r.vuln_type;
    acc[label] = (acc[label] ?? 0) + 1;
    return acc;
  }, {});
  const barData = Object.entries(vulnTypeCounts).map(([name, value]) => ({
    name,
    value,
  }));

  const criticalCount =
    (severityCounts["CRITICAL"] ?? 0) + (severityCounts["HIGH"] ?? 0);
  const scannedAt = results[0]?.scanned_at
    ? new Date(results[0].scanned_at).toLocaleString("en-US")
    : new Date().toLocaleString("en-US");

  // 채팅 모달 열기
  const openChat = (step: any) => {
    if (!selected) return;
    setChatContext({
      vuln_type: selected.vuln_type,
      severity: selected.severity,
      url: selected.url,
      parameter: selected.parameter,
      payload: selected.payload,
      action: typeof step === "string" ? step : (step.action ?? ""),
      reason: typeof step === "string" ? "" : (step.reason ?? ""),
    });
  };

  const handleDownloadPDF = async () => {
    if (isDownloading) return;
    setIsDownloading(true);
    try {
      const fontRes = await fetch("/NanumGothic.ttf", { cache: "force-cache" });
      if (!fontRes.ok) throw new Error("폰트 로드 실패");
      const fontBytes = await fontRes.arrayBuffer();
      const pdfDoc = await PDFDocument.create();
      pdfDoc.registerFontkit(fontkit);
      const korFont = await pdfDoc.embedFont(fontBytes, { subset: false });
      const PW = 595,
        PH = 842,
        ML = 40,
        MR = 40,
        CW = PW - ML - MR;
      let page = pdfDoc.addPage([PW, PH]);
      let y = PH - 50;
      const SEVERITY_COLOR_RGB: Record<string, [number, number, number]> = {
        CRITICAL: [239 / 255, 68 / 255, 68 / 255],
        HIGH: [249 / 255, 115 / 255, 22 / 255],
        MEDIUM: [234 / 255, 179 / 255, 8 / 255],
        LOW: [34 / 255, 197 / 255, 94 / 255],
        SAFE: [156 / 255, 163 / 255, 175 / 255],
      };
      const checkPage = (need: number) => {
        if (y - need < 40) {
          page = pdfDoc.addPage([PW, PH]);
          y = PH - 50;
        }
      };
      const drawHLine = () => {
        page.drawLine({
          start: { x: ML, y },
          end: { x: PW - MR, y },
          thickness: 0.5,
          color: rgb(0.85, 0.85, 0.85),
        });
        y -= 10;
      };
      const drawText = (
        text: string,
        x: number,
        yPos: number,
        size: number,
        color = rgb(0.1, 0.1, 0.1),
        maxWidth?: number,
      ) => {
        let d = text;
        if (maxWidth) {
          while (d.length > 1 && korFont.widthOfTextAtSize(d, size) > maxWidth)
            d = d.slice(0, -1);
          if (d !== text) d = d.slice(0, -1) + "…";
        }
        page.drawText(d, { x, y: yPos, size, font: korFont, color });
      };
      drawText(
        "Web Vulnerability Scan Report",
        ML,
        y,
        18,
        rgb(0.06, 0.09, 0.16),
      );
      y -= 22;
      drawText(`대상: ${scannedUrl || "N/A"}`, ML, y, 9, rgb(0.39, 0.45, 0.55));
      y -= 13;
      drawText(
        `스캔 일시: ${results[0]?.scanned_at ? new Date(results[0].scanned_at).toLocaleString("ko-KR") : new Date().toLocaleString("ko-KR")}`,
        ML,
        y,
        9,
        rgb(0.39, 0.45, 0.55),
      );
      y -= 14;
      drawHLine();
      drawText("요약", ML, y, 13, rgb(0.06, 0.09, 0.16));
      y -= 16;
      const sevLabels = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "SAFE"];
      const sevKor: Record<string, string> = {
        CRITICAL: "치명적",
        HIGH: "높음",
        MEDIUM: "보통",
        LOW: "낮음",
        SAFE: "안전",
      };
      const boxW = CW / 5;
      sevLabels.forEach((sev, i) => {
        const x = ML + i * boxW;
        const count = severityCounts[sev] ?? 0;
        const [r, g, b] = SEVERITY_COLOR_RGB[sev];
        page.drawRectangle({
          x,
          y: y - 30,
          width: boxW - 4,
          height: 38,
          color: rgb(r, g, b),
        });
        drawText(String(count), x + boxW / 2 - 8, y - 10, 16, rgb(1, 1, 1));
        drawText(sevKor[sev], x + 4, y - 25, 7, rgb(1, 1, 1));
      });
      y -= 46;
      drawHLine();
      checkPage(60);
      drawText("취약점 목록", ML, y, 13, rgb(0.06, 0.09, 0.16));
      y -= 16;
      page.drawRectangle({
        x: ML,
        y: y - 18,
        width: CW,
        height: 20,
        color: rgb(0.95, 0.97, 0.99),
      });
      drawText("#", ML + 4, y - 12, 8, rgb(0.39, 0.45, 0.55));
      drawText("심각도", ML + 20, y - 12, 8, rgb(0.39, 0.45, 0.55));
      drawText("유형", ML + 90, y - 12, 8, rgb(0.39, 0.45, 0.55));
      drawText("파라미터", ML + 155, y - 12, 8, rgb(0.39, 0.45, 0.55));
      drawText("CVSS", ML + 250, y - 12, 8, rgb(0.39, 0.45, 0.55));
      drawText("URL", ML + 290, y - 12, 8, rgb(0.39, 0.45, 0.55));
      y -= 22;
      results.forEach((item, i) => {
        checkPage(22);
        const [r, g, b] =
          SEVERITY_COLOR_RGB[item.severity] ?? SEVERITY_COLOR_RGB.SAFE;
        const sevLabel = SEVERITY_META[item.severity]?.label ?? item.severity;
        page.drawRectangle({
          x: ML,
          y: y - 16,
          width: CW,
          height: 20,
          color: i % 2 === 0 ? rgb(1, 1, 1) : rgb(0.98, 0.99, 1),
        });
        page.drawRectangle({
          x: ML + 18,
          y: y - 13,
          width: korFont.widthOfTextAtSize(sevLabel, 7) + 10,
          height: 14,
          color: rgb(r, g, b),
        });
        drawText(sevLabel, ML + 20, y - 7, 7, rgb(1, 1, 1));
        drawText(String(i + 1), ML + 4, y - 7, 8);
        drawText(
          VULN_TYPE_LABEL[item.vuln_type] ?? item.vuln_type,
          ML + 90,
          y - 7,
          8,
          rgb(0.2, 0.2, 0.2),
          60,
        );
        drawText(
          item.parameter || "-",
          ML + 155,
          y - 7,
          8,
          rgb(0.2, 0.2, 0.2),
          90,
        );
        drawText(
          String(SEVERITY_SCORE[item.severity] ?? 0),
          ML + 250,
          y - 7,
          8,
        );
        drawText(item.url, ML + 290, y - 7, 7, rgb(0.4, 0.4, 0.4), CW - 250);
        y -= 20;
      });
      y -= 4;
      drawHLine();
      for (let i = 0; i < results.length; i++) {
        const item = results[i];
        let itemVulnInfo: any = null;
        try {
          const infoRes = await fetch(`${BACKEND_URL}/vuln-info/by-result`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              vuln_type: item.vuln_type,
              severity: item.severity,
              url: item.url,
              parameter: item.parameter,
              payload: item.payload,
              evidence: item.evidence,
              source: item.source,
              reflection: item.reflection,
            }),
          });
          if (infoRes.ok) itemVulnInfo = await infoRes.json();
        } catch {}
        checkPage(80);
        drawText(
          `[${i + 1}] ${VULN_TYPE_LABEL[item.vuln_type]} — ${item.parameter || "-"}`,
          ML,
          y,
          12,
          rgb(0.06, 0.09, 0.16),
        );
        y -= 14;
        const [r, g, b] =
          SEVERITY_COLOR_RGB[item.severity] ?? SEVERITY_COLOR_RGB.SAFE;
        const badge = `${SEVERITY_META[item.severity]?.label}  CVSS ${SEVERITY_SCORE[item.severity]}`;
        page.drawRectangle({
          x: ML,
          y: y - 14,
          width: korFont.widthOfTextAtSize(badge, 8) + 14,
          height: 18,
          color: rgb(r, g, b),
        });
        drawText(badge, ML + 7, y - 8, 8, rgb(1, 1, 1));
        y -= 24;
        drawText("1. 기본 정보", ML + 4, y, 9, rgb(0.2, 0.2, 0.6));
        y -= 14;
        const basics: [string, string][] = [
          ["취약점명", VULN_TYPE_LABEL[item.vuln_type]],
          [
            "위험도",
            `${SEVERITY_META[item.severity]?.label} (CVSS ${SEVERITY_SCORE[item.severity]})`,
          ],
          ["발견 URL", item.url],
          ["파라미터명", item.parameter || "-"],
          ["출처", item.source || "-"],
        ];
        basics.forEach(([label, value]) => {
          checkPage(14);
          drawText(`  ${label}:`, ML + 4, y, 8, rgb(0.39, 0.45, 0.55));
          drawText(value, ML + 80, y, 8, rgb(0.15, 0.15, 0.15), CW - 80);
          y -= 13;
        });
        y -= 4;
        if (itemVulnInfo?.ai_description) {
          drawText("2. AI 상세 분석", ML + 4, y, 9, rgb(0.2, 0.2, 0.6));
          y -= 13;
          let line = "";
          [...itemVulnInfo.ai_description].forEach((ch) => {
            const t = line + ch;
            if (korFont.widthOfTextAtSize(t, 8) > CW - 10) {
              checkPage(12);
              drawText(line, ML + 8, y, 8, rgb(0.25, 0.35, 0.55));
              y -= 11;
              line = ch;
            } else line = t;
          });
          if (line) {
            checkPage(12);
            drawText(line, ML + 8, y, 8, rgb(0.25, 0.35, 0.55));
            y -= 11;
          }
          y -= 4;
        }
        drawText("3. 탐지 근거", ML + 4, y, 9, rgb(0.2, 0.2, 0.6));
        y -= 13;
        [
          ["증거", item.evidence],
          ["페이로드", item.payload || "-"],
        ].forEach(([label, value]) => {
          checkPage(14);
          drawText(`  ${label}:`, ML + 4, y, 8, rgb(0.39, 0.45, 0.55));
          let line = "";
          [...value].forEach((ch) => {
            const t = line + ch;
            if (korFont.widthOfTextAtSize(t, 8) > CW - 80) {
              drawText(line, ML + 70, y, 8, rgb(0.15, 0.15, 0.15));
              y -= 12;
              checkPage(14);
              line = ch;
            } else line = t;
          });
          if (line) {
            drawText(line, ML + 70, y, 8, rgb(0.15, 0.15, 0.15));
            y -= 14;
          }
        });
        y -= 4;
        if (
          item.vuln_type !== "none" &&
          itemVulnInfo?.remediation?.length > 0
        ) {
          drawText("4. 대응방안", ML + 4, y, 9, rgb(0.2, 0.2, 0.6));
          y -= 13;
          itemVulnInfo.remediation.forEach((step: any, si: number) => {
            checkPage(20);
            const action =
              typeof step === "string" ? step : step.action || "대응방안 없음";
            const reason =
              typeof step === "object" && step.reason
                ? ` (${step.reason})`
                : "";
            const full = `${si + 1}. ${action}${reason}`;
            let line = "";
            let isFirst = true;
            [...full].forEach((ch) => {
              const t = line + ch;
              if (korFont.widthOfTextAtSize(t, 8) > CW - 10) {
                drawText(
                  line,
                  ML + (isFirst ? 4 : 14),
                  y,
                  8,
                  rgb(0.12, 0.23, 0.54),
                );
                y -= 11;
                checkPage(14);
                line = ch;
                isFirst = false;
              } else line = t;
            });
            if (line) {
              drawText(
                line,
                ML + (isFirst ? 4 : 14),
                y,
                8,
                rgb(0.12, 0.23, 0.54),
              );
              y -= 13;
            }
          });
        }
        y -= 6;
        drawHLine();
      }
      page.drawText(
        `Web Vulnerability Scanner  |  생성일: ${new Date().toLocaleString("ko-KR")}`,
        { x: ML, y: 25, size: 8, font: korFont, color: rgb(0.7, 0.7, 0.7) },
      );
      const pdfBytes = await pdfDoc.save();
      const blob = new Blob([pdfBytes.buffer as ArrayBuffer], {
        type: "application/pdf",
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `vulnerability-report-${Date.now()}.pdf`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      console.error("PDF 생성 실패:", err);
      alert("PDF 생성 중 오류가 발생했습니다.");
    } finally {
      setIsDownloading(false);
    }
  };

  return (
    <div className="min-h-screen bg-slate-100 p-6 font-sans text-gray-800">
      <div className="max-w-6xl mx-auto">
        <div className="flex items-center justify-between mb-6">
          <button
            onClick={() => router.back()}
            className="flex items-center gap-2 text-gray-500 hover:text-gray-800 transition-colors text-sm font-medium"
          >
            <ArrowLeft size={16} /> 돌아가기
          </button>
          <h1 className="text-2xl font-bold text-slate-900">
            취약점 상세 리포트
          </h1>
          <button
            onClick={handleDownloadPDF}
            disabled={isDownloading || results.length === 0}
            className={`flex items-center gap-2 px-5 py-2.5 rounded-lg font-bold text-white text-sm shadow-md transition-all active:scale-95 ${isDownloading || results.length === 0 ? "bg-gray-300 cursor-not-allowed" : "bg-slate-700 hover:bg-slate-900"}`}
          >
            <Download size={16} />{" "}
            {isDownloading ? "생성 중..." : "PDF 다운로드"}
          </button>
        </div>

        <div
          ref={reportRef}
          className="bg-white rounded-2xl shadow-sm border border-gray-100 p-8"
        >
          {/* 헤더 */}
          <div className="mb-8 pb-6 border-b border-gray-100">
            <div className="flex items-start justify-between">
              <div>
                <h2 className="text-xl font-bold text-slate-900 mb-1">
                  🛡️ Web Vulnerability Scan Report
                </h2>
                <div className="flex items-center gap-2 text-sm text-gray-500 mt-2">
                  <Globe size={13} />
                  <span className="font-mono text-blue-600 break-all">
                    {scannedUrl || "URL 정보 없음"}
                  </span>
                </div>
                <div className="flex items-center gap-2 text-xs text-gray-400 mt-1">
                  <Clock size={12} />
                  <span>스캔 완료: {scannedAt}</span>
                </div>
              </div>
              <div className="text-right">
                <div className="text-3xl font-black text-red-500">
                  {criticalCount}
                </div>
                <div className="text-xs text-gray-400">Critical / High</div>
                <div className="text-lg font-bold text-gray-700 mt-1">
                  {results.length}건
                </div>
                <div className="text-xs text-gray-400">총 취약점</div>
              </div>
            </div>
          </div>

          {/* 심각도 뱃지 */}
          <div className="grid grid-cols-5 gap-3 mb-8">
            {(["CRITICAL", "HIGH", "MEDIUM", "LOW", "SAFE"] as const).map(
              (sev) => {
                const meta = SEVERITY_META[sev];
                const count = severityCounts[sev] ?? 0;
                return (
                  <div
                    key={sev}
                    className={`rounded-xl p-4 text-center border ${meta.bg} ${meta.border}`}
                  >
                    <div className={`text-2xl font-black ${meta.text}`}>
                      {count}
                    </div>
                    <div className={`text-xs font-bold ${meta.text} mt-1`}>
                      {meta.label}
                    </div>
                  </div>
                );
              },
            )}
          </div>

          {/* 차트 */}
          {results.length > 0 && (
            <div className="grid grid-cols-2 gap-6 mb-8">
              <div className="border border-gray-100 rounded-xl p-5">
                <h3 className="font-bold text-sm text-gray-600 mb-4">
                  심각도 분포
                </h3>
                <div className="flex items-center justify-center gap-6">
                  <PieChart width={160} height={160}>
                    <Pie
                      data={pieData}
                      innerRadius={45}
                      outerRadius={70}
                      paddingAngle={4}
                      dataKey="value"
                      stroke="none"
                    >
                      {pieData.map((entry, i) => (
                        <Cell key={i} fill={entry.color} />
                      ))}
                    </Pie>
                    <Tooltip
                      contentStyle={{
                        borderRadius: "10px",
                        border: "1px solid #f3f4f6",
                        fontSize: "12px",
                      }}
                    />
                  </PieChart>
                  <div className="space-y-1.5">
                    {pieData.map((entry) => (
                      <div
                        key={entry.name}
                        className="flex items-center gap-2 text-xs"
                      >
                        <div
                          className="w-2.5 h-2.5 rounded-full"
                          style={{ backgroundColor: entry.color }}
                        />
                        <span className="text-gray-600">{entry.name}</span>
                        <span className="font-bold text-gray-800">
                          {entry.value}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
              <div className="border border-gray-100 rounded-xl p-5">
                <h3 className="font-bold text-sm text-gray-600 mb-4">
                  취약점 유형
                </h3>
                <div className="overflow-x-auto">
                  <BarChart
                    width={450}
                    height={160}
                    data={barData}
                    layout="vertical"
                  >
                    <XAxis type="number" hide />
                    <YAxis
                      dataKey="name"
                      type="category"
                      width={90}
                      tick={{ fontSize: 11, fill: "#555" }}
                      axisLine={false}
                      tickLine={false}
                    />
                    <Tooltip
                      contentStyle={{
                        borderRadius: "10px",
                        border: "1px solid #f3f4f6",
                        fontSize: "12px",
                      }}
                    />
                    <Bar
                      dataKey="value"
                      fill="#6366f1"
                      radius={[0, 4, 4, 0]}
                      barSize={18}
                    />
                  </BarChart>
                </div>
              </div>
            </div>
          )}

          {/* 취약점 목록 */}
          <div className="mb-8">
            <h3 className="font-bold text-sm text-gray-600 mb-3 flex items-center gap-2">
              <ShieldAlert size={15} /> 탐지된 취약점 목록
            </h3>
            {results.length === 0 ? (
              <div className="text-center py-12 text-gray-400 text-sm italic border border-gray-100 rounded-xl">
                탐지된 취약점이 없습니다.
              </div>
            ) : (
              (["xss", "sqli", "none"] as const)
                .filter((type) => results.some((r) => r.vuln_type === type))
                .map((type) => {
                  const typeResults = results.filter(
                    (r) => r.vuln_type === type,
                  );
                  const TAB_COLOR: Record<string, string> = {
                    xss: "bg-orange-500",
                    sqli: "bg-red-600",
                    none: "bg-gray-400",
                  };
                  return (
                    <div key={type} className="mb-6">
                      <div
                        className={`flex items-center gap-2 px-4 py-2 rounded-t-xl text-white font-bold text-sm ${TAB_COLOR[type]}`}
                      >
                        <span>{VULN_TYPE_LABEL[type]}</span>
                        <span className="bg-white bg-opacity-30 text-white text-xs px-2 py-0.5 rounded-full">
                          {typeResults.length}건
                        </span>
                      </div>
                      <div className="border border-gray-100 rounded-b-xl overflow-hidden">
                        <table className="w-full text-sm">
                          <thead>
                            <tr className="bg-gray-50 border-b border-gray-100">
                              <th className="text-left p-3 text-xs text-gray-500 font-bold">
                                #
                              </th>
                              <th className="text-left p-3 text-xs text-gray-500 font-bold">
                                심각도
                              </th>
                              <th className="text-left p-3 text-xs text-gray-500 font-bold">
                                파라미터
                              </th>
                              <th className="text-left p-3 text-xs text-gray-500 font-bold">
                                CVSS
                              </th>
                              <th className="text-left p-3 text-xs text-gray-500 font-bold">
                                URL
                              </th>
                            </tr>
                          </thead>
                          <tbody>
                            {typeResults.map((item, i) => {
                              const meta =
                                SEVERITY_META[item.severity] ??
                                SEVERITY_META.SAFE;
                              return (
                                <tr
                                  key={i}
                                  onClick={() => {
                                    setSelected(item);
                                    fetchVulnInfo(item);
                                  }}
                                  className={`border-b border-gray-50 cursor-pointer transition-colors ${selected === item ? "bg-blue-50" : "hover:bg-gray-50"}`}
                                >
                                  <td className="p-3 text-gray-400 text-xs">
                                    {i + 1}
                                  </td>
                                  <td className="p-3">
                                    <span
                                      className={`text-[10px] px-2 py-0.5 rounded border font-bold ${meta.bg} ${meta.text} ${meta.border}`}
                                    >
                                      {meta.label}
                                    </span>
                                  </td>
                                  <td className="p-3 text-xs text-gray-600 font-mono">
                                    {item.parameter || "-"}
                                  </td>
                                  <td className="p-3 text-xs font-bold text-gray-700">
                                    {SEVERITY_SCORE[item.severity]}
                                  </td>
                                  <td className="p-3 text-xs text-gray-400 truncate max-w-50 font-mono">
                                    {item.url}
                                  </td>
                                </tr>
                              );
                            })}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  );
                })
            )}
          </div>

          {/* 상세 분석 */}
          {selected && (
            <div className="border border-gray-100 rounded-xl overflow-hidden">
              <div className="bg-slate-800 text-white px-6 py-4 flex items-center gap-3">
                <Tag size={15} />
                <span className="font-bold text-sm">취약점 상세 분석</span>
                <span
                  className={`ml-auto text-[11px] px-3 py-1 rounded-full font-bold ${SEVERITY_META[selected.severity]?.bg} ${SEVERITY_META[selected.severity]?.text}`}
                >
                  {SEVERITY_META[selected.severity]?.label} · CVSS{" "}
                  {SEVERITY_SCORE[selected.severity]}
                </span>
              </div>
              <div className="p-6 space-y-6">
                {/* 1. 기본 정보 */}
                <div>
                  <div className="flex items-center gap-2 mb-3">
                    <span className="bg-slate-700 text-white text-[10px] font-black px-2 py-0.5 rounded">
                      1
                    </span>
                    <span className="font-bold text-sm text-gray-700">
                      기본 정보
                    </span>
                  </div>
                  <div className="grid grid-cols-3 gap-3">
                    {[
                      {
                        label: "취약점명",
                        value: VULN_TYPE_LABEL[selected.vuln_type],
                      },
                      {
                        label: "위험도",
                        value: `${SEVERITY_META[selected.severity]?.label} (CVSS ${SEVERITY_SCORE[selected.severity]})`,
                      },
                      { label: "발견 URL", value: selected.url },
                      { label: "파라미터명", value: selected.parameter || "-" },
                      { label: "출처", value: selected.source || "-" },
                      {
                        label: "스캔 시각",
                        value: new Date(selected.scanned_at).toLocaleString(
                          "ko-KR",
                        ),
                      },
                    ].map(({ label, value }) => (
                      <div key={label} className="bg-gray-50 rounded-lg p-3">
                        <span className="text-[10px] text-gray-400 font-bold block mb-1">
                          {label}
                        </span>
                        <span className="text-xs text-gray-700 font-medium break-all">
                          {value}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
                <div className="border-t border-gray-100" />

                {/* 2. 취약점 설명 */}
                <div>
                  <div className="flex items-center gap-2 mb-3">
                    <span className="bg-slate-700 text-white text-[10px] font-black px-2 py-0.5 rounded">
                      2
                    </span>
                    <span className="font-bold text-sm text-gray-700">
                      취약점 설명
                    </span>
                    {vulnInfoLoading && (
                      <span className="text-[10px] text-blue-500 bg-blue-50 px-2 py-0.5 rounded-full">
                        로딩 중...
                      </span>
                    )}
                  </div>
                  <div className="bg-gray-50 rounded-lg p-4 text-xs text-gray-700 leading-relaxed">
                    {vulnInfo?.description ?? "불러오는 중..."}
                  </div>
                </div>

                {/* 2-1. AI 상세 분석 */}
                {(vulnInfoLoading || vulnInfo?.ai_description) && (
                  <div>
                    <div className="flex items-center gap-2 mb-3">
                      <span className="bg-indigo-600 text-white text-[10px] font-black px-2 py-0.5 rounded">
                        AI
                      </span>
                      <Bot size={14} className="text-indigo-500" />
                      <span className="font-bold text-sm text-gray-700">
                        AI 상세 분석
                      </span>
                      {vulnInfoLoading && (
                        <span className="text-[10px] text-indigo-500 bg-indigo-50 px-2 py-0.5 rounded-full">
                          분석 중...
                        </span>
                      )}
                    </div>
                    <div className="bg-indigo-50 border border-indigo-100 rounded-lg p-4 space-y-2">
                      {vulnInfoLoading ? (
                        <p className="text-xs text-indigo-400 italic">
                          AI가 이 취약점을 분석하고 있습니다...
                        </p>
                      ) : (
                        <AiDescriptionBlock
                          text={vulnInfo?.ai_description ?? ""}
                        />
                      )}
                    </div>
                  </div>
                )}
                <div className="border-t border-gray-100" />

                {/* 3. 실제 피해 가능성 */}
                <div>
                  <div className="flex items-center gap-2 mb-3">
                    <span className="bg-slate-700 text-white text-[10px] font-black px-2 py-0.5 rounded">
                      3
                    </span>
                    <span className="font-bold text-sm text-gray-700">
                      실제 피해 가능성
                    </span>
                    {vulnInfoLoading && (
                      <span className="text-[10px] text-blue-500 bg-blue-50 px-2 py-0.5 rounded-full">
                        로딩 중...
                      </span>
                    )}
                  </div>
                  <div className="bg-red-50 border border-red-100 rounded-lg p-4 text-xs text-red-700 leading-relaxed">
                    {vulnInfo?.impact ? (
                      Array.isArray(vulnInfo.impact) ? (
                        <ul className="space-y-1">
                          {vulnInfo.impact.map((imp, i) => (
                            <li key={i} className="flex gap-2">
                              <span className="shrink-0">•</span>
                              <span>{imp}</span>
                            </li>
                          ))}
                        </ul>
                      ) : (
                        String(vulnInfo.impact)
                      )
                    ) : (
                      "불러오는 중..."
                    )}
                  </div>
                </div>
                <div className="border-t border-gray-100" />

                {/* 4. 탐지 근거 */}
                <div>
                  <div className="flex items-center gap-2 mb-3">
                    <span className="bg-slate-700 text-white text-[10px] font-black px-2 py-0.5 rounded">
                      4
                    </span>
                    <span className="font-bold text-sm text-gray-700">
                      탐지 근거 (Evidence)
                    </span>
                  </div>
                  <div className="grid grid-cols-2 gap-3">
                    <div>
                      <span className="text-[10px] text-gray-400 font-bold block mb-1.5">
                        증거
                      </span>
                      <div className="bg-gray-50 rounded-lg p-3 text-xs text-gray-700 min-h-12">
                        {selected.evidence || "-"}
                      </div>
                    </div>
                    <div>
                      <span className="text-[10px] text-gray-400 font-bold block mb-1.5">
                        반사 방식
                      </span>
                      <div className="bg-gray-50 rounded-lg p-3 text-xs text-gray-700 min-h-12">
                        {selected.reflection || "-"}
                      </div>
                    </div>
                    <div className="col-span-2">
                      <span className="text-[10px] text-gray-400 font-bold block mb-1.5">
                        사용된 페이로드
                      </span>
                      <div className="bg-slate-900 rounded-lg p-3 font-mono text-xs text-green-400 break-all min-h-12">
                        {selected.payload || "// 페이로드 없음"}
                      </div>
                    </div>
                  </div>
                </div>
                <div className="border-t border-gray-100" />

                {/* 5. 대응방안 — 버튼 추가 */}
                {selected.vuln_type !== "none" && (
                  <div>
                    <div className="flex items-center gap-2 mb-3">
                      <span className="bg-slate-700 text-white text-[10px] font-black px-2 py-0.5 rounded">
                        5
                      </span>
                      <span className="font-bold text-sm text-gray-700">
                        대응방안
                      </span>
                      {vulnInfoLoading && (
                        <span className="text-[10px] text-blue-500 bg-blue-50 px-2 py-0.5 rounded-full">
                          로딩 중...
                        </span>
                      )}
                    </div>
                    <div className="space-y-3">
                      {vulnInfo?.remediation ? (
                        vulnInfo.remediation.map((step: any, i: number) => (
                          <div
                            key={i}
                            className="bg-blue-50 border border-blue-100 rounded-xl p-4"
                          >
                            {/* action */}
                            <div className="flex gap-2 items-start mb-2">
                              <span className="shrink-0 bg-blue-500 text-white text-[10px] font-black w-5 h-5 rounded-full flex items-center justify-center mt-0.5">
                                {i + 1}
                              </span>
                              <p className="text-xs font-bold text-blue-900 leading-relaxed flex-1">
                                {typeof step === "string" ? step : step.action}
                              </p>
                            </div>
                            {/* reason */}
                            {typeof step !== "string" && step.reason && (
                              <div className="ml-7 mt-1 border-l-2 border-blue-200 pl-3">
                                <ReasonText text={step.reason} />
                              </div>
                            )}
                            {/* ★ AI 상담 버튼 ★ */}
                            <div className="ml-7 mt-3">
                              <button
                                onClick={() => openChat(step)}
                                className="flex items-center gap-1.5 text-[11px] font-bold text-slate-600 hover:text-slate-900 hover:bg-slate-100 px-3 py-1.5 rounded-lg transition-all active:scale-95 border border-slate-200 hover:border-slate-300 shadow-sm"
                              >
                                <MessageCircle size={12} />
                                AI에게 더 물어보기
                              </button>
                            </div>
                          </div>
                        ))
                      ) : (
                        <p className="text-xs text-gray-400 italic px-1">
                          대응방안을 불러오는 중입니다...
                        </p>
                      )}
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}

          <div className="mt-8 pt-4 border-t border-gray-100 flex justify-between items-center text-xs text-gray-300">
            <span>🛡️ Web Vulnerability Scanner — AI 기반 자동 탐지 시스템</span>
            <span>Generated at {new Date().toLocaleString("ko-KR")}</span>
          </div>
        </div>
      </div>

      {/* 채팅 모달 */}
      {chatContext && (
        <ChatModal
          context={chatContext}
          onClose={() => setChatContext(null)}
          backendUrl={BACKEND_URL}
        />
      )}
    </div>
  );
}
