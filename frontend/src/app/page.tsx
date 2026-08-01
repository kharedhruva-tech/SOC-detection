'use client';

import { useEffect } from 'react';
import { useRouter } from 'next/navigation';

export default function Home() {
  const router = useRouter();

  useEffect(() => {
    if (localStorage.getItem('soc_token')) {
      router.replace('/dashboard');
    } else {
      router.replace('/login');
    }
  }, [router]);

  return (
    <div className="flex min-h-screen items-center justify-center bg-[#04050d] text-slate-300 font-mono text-sm">
      <div className="flex items-center gap-3 border border-slate-800 bg-[#070919] p-6 rounded-xl shadow-2xl">
        <div className="w-3 h-3 rounded-full bg-[#00f0ff] animate-ping" />
        <span>Initializing AEGIS SOC Command Center...</span>
      </div>
    </div>
  );
}
