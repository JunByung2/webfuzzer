"use client";

import React, { useEffect, useState, useMemo } from "react";
import {
  PieChart,
  Pie,
  Cell,
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  BarChart,
  Bar,
} from "recharts";

const BACKEND_URL =
  process.env.NEXT_PUBLIC_BACKEND_URL ?? "http://localhost:5000";

interface DashboardStats {
  total_scans: number;
  recent_scan_date: string | null;
  today_scan_count: number;
  severity_counts: Record<string, number>;
  vuln_type_counts: Record<string, number>;
  trend_data: Array<{ day: string; count: number }>;
}

const SEVERITY_COLOR: Record<string, string> = {
  CRITICAL: "#ef4444",
  HIGH: "#f97316",
  MEDIUM: "#eab308",
  LOW: "#22c55e",
  SAFE: "#9ca3af",
};

const CARD_STYLE =
  "bg-white p-8 rounded-3xl border border-gray-100 shadow-sm flex flex-col items-center min-w-0 overflow-hidden";

export default function Dashboard() {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
  }, []);

  useEffect(() => {
    const fetchStats = async () => {
      try {
        const res = await fetch(`${BACKEND_URL}/dashboard`);

        if (!res.ok) {
          throw new Error(`대시보드 API 오류 (${res.status})`);
        }

        const data: DashboardStats = await res.json();
        setStats(data);
      } catch (err) {
        setError(err instanceof Error ? err.message : "데이터 로드 실패");
      } finally {
        setLoading(false);
      }
    };

    fetchStats();
  }, []);

  const pieData = useMemo(
    () =>
      Object.entries(
        stats?.severity_counts ?? {
          HIGH: 0,
          MEDIUM: 0,
          LOW: 0,
        },
      ).map(([name, value]) => ({
        name,
        value,
        color: SEVERITY_COLOR[name] ?? "#9ca3af",
      })),
    [stats],
  );

  const lineData = useMemo(
    () =>
      stats?.trend_data ?? [
        { day: "01", count: 0 },
        { day: "05", count: 0 },
        { day: "10", count: 0 },
        { day: "15", count: 0 },
        { day: "20", count: 0 },
        { day: "25", count: 0 },
        { day: "30", count: 0 },
      ],
    [stats],
  );

  const barData = useMemo(
    () =>
      Object.entries(
        stats?.vuln_type_counts ?? {
          sqli: 0,
          xss: 0,
          none: 0,
        },
      ).map(([name, value]) => ({
        name:
          name === "none" ? "Safe" : name === "sqli" ? "SQL Injection" : "XSS",
        value,
      })),
    [stats],
  );

  const summaryItems = [
    {
      label: "총 스캔 횟수",
      value: loading ? "로딩 중..." : `${stats?.total_scans ?? 0}회`,
    },
    {
      label: "최근 스캔일",
      value: loading ? "로딩 중..." : (stats?.recent_scan_date ?? "없음"),
    },
    {
      label: "오늘 감지",
      value: loading ? "로딩 중..." : `${stats?.today_scan_count ?? 0}회`,
      red: true,
    },
  ];

  if (!mounted) {
    return <div className="min-h-screen bg-slate-50" />;
  }

  return (
    <div className="min-h-screen bg-slate-50 overflow-x-hidden">
      <main className="max-w-6xl mx-auto mt-10 p-6">
        <header className="mb-10 text-center">
          <h2 className="text-4xl font-bold mb-4">
            Welcome to Web Vulnerability
          </h2>

          <p className="text-gray-500">
            AI 기반 웹 취약점 탐지 시스템에 대한 실시간 통계를 확인하세요.
          </p>
        </header>

        {error && (
          <div className="mb-6 rounded-2xl bg-red-50 border border-red-200 p-4 text-red-700">
            {error}
          </div>
        )}

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-10">
          {summaryItems.map((item, idx) => (
            <div
              key={idx}
              className="border p-5 rounded-2xl bg-white shadow-sm text-center min-w-0"
            >
              <span className="text-gray-500 text-sm font-bold block mb-1">
                {item.label}
              </span>

              <span
                className={`ml-2 font-bold text-lg ${
                  item.red ? "text-red-500" : "text-gray-700"
                }`}
              >
                {item.value}
              </span>
            </div>
          ))}
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 min-w-0">
          {/* PIE CHART */}
          <section className={CARD_STYLE}>
            <h3 className="text-lg font-bold mb-2 text-gray-800">총 취약점</h3>

            <div className="w-full h-px bg-gray-100 mb-6" />

            <div className="flex justify-center w-full overflow-hidden">
              <PieChart width={300} height={260}>
                <Pie
                  data={pieData}
                  innerRadius={55}
                  outerRadius={75}
                  paddingAngle={5}
                  dataKey="value"
                  stroke="none"
                >
                  {pieData.map((entry, index) => (
                    <Cell key={index} fill={entry.color} />
                  ))}
                </Pie>

                <Tooltip
                  contentStyle={{
                    borderRadius: "12px",
                    border: "1px solid #f3f4f6",
                  }}
                />
              </PieChart>
            </div>
          </section>

          {/* LINE CHART */}
          <section className={CARD_STYLE}>
            <h3 className="text-lg font-bold mb-2 text-gray-800">
              취약점 추이
            </h3>

            <div className="w-full h-px bg-gray-100 mb-6" />

            <div className="overflow-x-auto w-full">
              <LineChart width={320} height={260} data={lineData}>
                <CartesianGrid strokeDasharray="3 3" vertical={false} />

                <XAxis dataKey="day" fontSize={12} />

                <YAxis fontSize={12} />

                <Tooltip />

                <Line
                  type="monotone"
                  dataKey="count"
                  stroke="#3b82f6"
                  strokeWidth={2}
                  dot={{ r: 4 }}
                />
              </LineChart>
            </div>
          </section>

          {/* BAR CHART */}
          <section className={CARD_STYLE}>
            <h3 className="text-lg font-bold mb-2 text-gray-800">
              취약점 유형
            </h3>

            <div className="w-full h-px bg-gray-100 mb-6" />

            <div className="overflow-x-auto w-full">
              <BarChart
                width={320}
                height={260}
                data={barData}
                layout="vertical"
              >
                <XAxis type="number" hide />

                <YAxis
                  dataKey="name"
                  type="category"
                  width={100}
                  fontSize={12}
                />

                <Tooltip cursor={{ fill: "transparent" }} />

                <Bar dataKey="value" fill="#6366f1" radius={[0, 4, 4, 0]} />
              </BarChart>
            </div>
          </section>
        </div>
      </main>
    </div>
  );
}
