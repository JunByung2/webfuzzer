"use client";
import Link from "next/link";
import React, { useEffect, useState } from "react";
import { useRouter } from "next/navigation";

export default function Navbar() {
  return (
    <nav className="bg-slate-900 text-white p-4 shadow-lg">
      <div className="max-w-5xl mx-auto flex justify-between items-center">
        <Link
          href="/"
          className="text-xl font-bold flex items-center gap-2 hover:opacity-80 transition-opacity"
        >
          🛡️ Web Vulnerability Scanner
        </Link>

        <div className="flex items-center gap-6 text-sm font-medium">
          <Link href="/" className="hover:text-blue-200 transition-colors">
            Home
          </Link>
          <Link href="/Scan" className="hover:text-blue-200 transition-colors">
            Scan
          </Link>
          <Link href="/Guide" className="hover:text-blue-200 transition-colors">
            Guide
          </Link>
        </div>
      </div>
    </nav>
  );
}
