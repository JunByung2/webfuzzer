"use client";
import React from "react";
// 그래프 라이브러리 (npm install recharts 필요)
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
  ResponsiveContainer,
  BarChart,
  Bar,
} from "recharts";

export default function Dashboard() {
  // 샘플 데이터
  const pieData = [
    { name: "High", value: 10, color: "#ef4444" },
    { name: "Medium", value: 15, color: "#f59e0b" },
    { name: "Low", value: 15, color: "#3b82f6" },
  ];

  const lineData = [
    { day: "01", count: 2 },
    { day: "05", count: 5 },
    { day: "10", count: 3 },
    { day: "15", count: 8 },
    { day: "20", count: 4 },
    { day: "25", count: 9 },
    { day: "30", count: 6 },
  ];

  const barData = [
    { name: "SQL Injection", value: 12 },
    { name: "XSS", value: 8 },
    { name: "Other", value: 5 },
  ];

  return (
    <div className="max-w-6xl mx-auto p-6 space-y-8">
      {/* 1. 상단 섹션 (기존 설명 유지) */}
      <header className="text-center py-10 border-b">
        <h2 className="text-4xl font-bold mb-4">
          Welcome to Web Vulnerability
        </h2>
        <p className="text-gray-500">
          AI 기반 웹 취약점 탐지 시스템에 대한 설명이 들어갑니다.
        </p>
      </header>

      {/* 2. 대시보드 요약 정보 (기획안의 3개 박스) */}
      <div className="grid grid-cols-3 gap-4">
        <div className="border p-4 rounded-xl bg-white shadow-sm text-center">
          <span className="text-gray-500 text-sm">총 스캔 횟수:</span>
          <span className="ml-2 font-bold text-lg">128회</span>
        </div>
        <div className="border p-4 rounded-xl bg-white shadow-sm text-center">
          <span className="text-gray-500 text-sm">최근 스캔일:</span>
          <span className="ml-2 font-bold text-lg">2026-04-04</span>
        </div>
        <div className="border p-4 rounded-xl bg-white shadow-sm text-center">
          <span className="text-gray-500 text-sm">오늘 감지:</span>
          <span className="ml-2 font-bold text-lg text-red-500">0건</span>
        </div>
      </div>

      {/* 3. 그래프 영역 (기획안의 하단 3개 차트) */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* 도넛 차트: 총 취약점 */}
        <div className="border p-6 rounded-2xl bg-white shadow-sm h-80 flex flex-col items-center">
          <h3 className="font-bold mb-4">총 취약점 (40개)</h3>
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie
                data={pieData}
                innerRadius={60}
                outerRadius={80}
                paddingAngle={5}
                dataKey="value"
              >
                {pieData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip />
            </PieChart>
          </ResponsiveContainer>
        </div>

        {/* 선 그래프: 취약점 추이 */}
        <div className="border p-6 rounded-2xl bg-white shadow-sm h-80">
          <h3 className="font-bold mb-4">취약점 추이 (최근 30일)</h3>
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={lineData}>
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
          </ResponsiveContainer>
        </div>

        {/* 바 차트: 취약점 유형 */}
        <div className="border p-6 rounded-2xl bg-white shadow-sm h-80">
          <h3 className="font-bold mb-4">취약점 유형</h3>
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={barData} layout="vertical">
              <XAxis type="number" hide />
              <YAxis dataKey="name" type="category" fontSize={10} width={80} />
              <Tooltip cursor={{ fill: "transparent" }} />
              <Bar dataKey="value" fill="#6366f1" radius={[0, 4, 4, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  );
}
