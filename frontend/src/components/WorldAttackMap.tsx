'use client';

import React, { useRef, useEffect } from 'react';

interface AttackArc {
  startX: number;
  startY: number;
  endX: number;
  endY: number;
  progress: number;
  speed: number;
  color: string;
  sender: string;
}

export default function WorldAttackMap() {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const arcsRef = useRef<AttackArc[]>([]);

  // Fixed location for center enterprise SOC (e.g. Washington D.C / East US region)
  const socX = 230;
  const socY = 120;

  // Potential attacking coordinates
  const attackOrigins = [
    { x: 550, y: 130, name: "Russia / APT29", color: "#ff0055" },
    { x: 620, y: 160, name: "China / RedFox", color: "#ffcc00" },
    { x: 120, y: 260, name: "South America / ThreatActor", color: "#bd00ff" },
    { x: 440, y: 240, name: "Africa / ProxyHost", color: "#00f0ff" },
    { x: 470, y: 110, name: "Europe / Tor Exit Node", color: "#ff3300" }
  ];

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let animationId: number;
    
    // Resize handler
    const resizeCanvas = () => {
      canvas.width = canvas.parentElement?.clientWidth || 800;
      canvas.height = 320;
    };
    resizeCanvas();
    window.addEventListener('resize', resizeCanvas);

    // Simulation loop
    const tick = () => {
      ctx.fillStyle = '#05060f';
      ctx.fillRect(0, 0, canvas.width, canvas.height);

      // 1. Draw World Grid Map mockup (subtle dots representation)
      ctx.fillStyle = 'rgba(255, 255, 255, 0.05)';
      const dotSpacing = 12;
      for (let x = 10; x < canvas.width; x += dotSpacing) {
        for (let y = 10; y < canvas.height; y += dotSpacing) {
          // Exclude some zones to vaguely represent continents (simple procedural map)
          const isLand = (
            (x > 50 && x < 280 && y > 60 && y < 190) || // North America
            (x > 150 && x < 250 && y >= 190 && y < 290) || // South America
            (x > 380 && x < 540 && y > 50 && y < 160) || // Europe
            (x > 410 && x < 520 && y >= 160 && y < 280) || // Africa
            (x > 530 && x < 750 && y > 60 && y < 220) || // Asia
            (x > 630 && x < 750 && y >= 220 && y < 300) // Australia
          );
          if (isLand) {
            ctx.fillRect(x, y, 2, 2);
          }
        }
      }

      // 2. Draw Enterprise Target SOC node
      // Scale coordinates relative to width/height map size
      const scaleX = (x: number) => (x / 800) * canvas.width;
      const scaleY = (y: number) => (y / 320) * canvas.height;

      const targetX = scaleX(socX);
      const targetY = scaleY(socY);

      // Target radar pulse
      const pulseRadius = (Date.now() / 25) % 30;
      ctx.beginPath();
      ctx.arc(targetX, targetY, pulseRadius, 0, Math.PI * 2);
      ctx.strokeStyle = 'rgba(0, 240, 255, ' + (1 - pulseRadius / 30) + ')';
      ctx.lineWidth = 1.5;
      ctx.stroke();

      // Target node core
      ctx.beginPath();
      ctx.arc(targetX, targetY, 5, 0, Math.PI * 2);
      ctx.fillStyle = '#00f0ff';
      ctx.fill();
      ctx.shadowColor = '#00f0ff';
      ctx.shadowBlur = 10;
      ctx.fillStyle = 'rgba(0, 240, 255, 0.4)';
      ctx.arc(targetX, targetY, 8, 0, Math.PI * 2);
      ctx.fill();
      ctx.shadowBlur = 0; // Reset

      // Target label
      ctx.fillStyle = 'rgba(0, 240, 255, 0.8)';
      ctx.font = '10px monospace';
      ctx.fillText("HQ-SOC-BASE", targetX - 30, targetY - 14);

      // 3. Randomly spawn new attack arcs
      if (Math.random() < 0.015 && arcsRef.current.length < 5) {
        const origin = attackOrigins[Math.floor(Math.random() * attackOrigins.length)];
        arcsRef.current.push({
          startX: scaleX(origin.x),
          startY: scaleY(origin.y),
          endX: targetX,
          endY: targetY,
          progress: 0,
          speed: 0.007 + Math.random() * 0.005,
          color: origin.color,
          sender: origin.name
        });
      }

      // 4. Draw & update active attack arcs
      arcsRef.current.forEach((arc, index) => {
        arc.progress += arc.speed;

        // Draw bezier arc curve
        ctx.beginPath();
        const midX = (arc.startX + arc.endX) / 2;
        const midY = (arc.startY + arc.endY) / 2 - 50; // Curve height offset
        
        ctx.strokeStyle = arc.color + '22'; // Faint line trace
        ctx.lineWidth = 1;
        ctx.moveTo(arc.startX, arc.startY);
        ctx.quadraticCurveTo(midX, midY, arc.endX, arc.endY);
        ctx.stroke();

        // Calculate active particle location on the curve (quadratic bezier formula)
        const t = arc.progress;
        const ptX = (1 - t) * (1 - t) * arc.startX + 2 * (1 - t) * t * midX + t * t * arc.endX;
        const ptY = (1 - t) * (1 - t) * arc.startY + 2 * (1 - t) * t * midY + t * t * arc.endY;

        // Draw active tracer particle
        ctx.shadowColor = arc.color;
        ctx.shadowBlur = 8;
        ctx.fillStyle = arc.color;
        ctx.beginPath();
        ctx.arc(ptX, ptY, 3, 0, Math.PI * 2);
        ctx.fill();
        ctx.shadowBlur = 0; // Reset

        // Origin details text
        if (arc.progress < 0.3) {
          ctx.fillStyle = 'rgba(255, 255, 255, 0.4)';
          ctx.font = '8px monospace';
          ctx.fillText(arc.sender, arc.startX - 20, arc.startY + 10);
        }

        // Handle collision at target
        if (arc.progress >= 1.0) {
          // Remove arc
          arcsRef.current.splice(index, 1);
        }
      });

      animationId = requestAnimationFrame(tick);
    };
    tick();

    return () => {
      cancelAnimationFrame(animationId);
      window.removeEventListener('resize', resizeCanvas);
    };
  }, []);

  return (
    <div className="relative w-full h-[320px] rounded-lg overflow-hidden border border-slate-800 bg-[#05060f]/60">
      <div className="absolute top-4 left-6 z-10 flex flex-col">
        <span className="text-[10px] text-slate-500 font-mono uppercase tracking-widest font-bold">
          Threat Vector Feed
        </span>
        <span className="text-sm font-semibold tracking-wide text-slate-200">
          Global Intrusion Map (Live)
        </span>
      </div>
      <div className="absolute top-4 right-6 z-10 flex gap-4 text-[10px] font-mono text-slate-400">
        <div className="flex items-center gap-1.5">
          <span className="w-2 h-2 rounded-full bg-neon-red" />
          <span>Wizard Spider</span>
        </div>
        <div className="flex items-center gap-1.5">
          <span className="w-2 h-2 rounded-full bg-neon-purple" />
          <span>APT29</span>
        </div>
      </div>
      <canvas ref={canvasRef} className="block w-full h-full" />
    </div>
  );
}
