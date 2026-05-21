'use client';

import { useEffect, useState } from 'react';

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8080';

export default function StrategiesPage() {
  const [strategies, setStrategies] = useState<any[]>([]);
  const [decisions, setDecisions] = useState<any[]>([]);

  useEffect(() => {
    const fetchData = async () => {
      const [sRes, dRes] = await Promise.all([
        fetch(`${API_URL}/api/strategies`).then(r => r.json()).catch(() => ({ strategies: [] })),
        fetch(`${API_URL}/api/decisions`).then(r => r.json()).catch(() => ({ decisions: [] })),
      ]);
      setStrategies(sRes.strategies || []);
      setDecisions(dRes.decisions || []);
    };
    fetchData();
    const interval = setInterval(fetchData, 5000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div>
      <h1 style={{ fontSize: '1.5rem', fontWeight: 700, marginBottom: '24px' }}>
        <span className="gradient-text">Containment Strategies</span>
      </h1>

      <h2 style={{ fontSize: '1.1rem', fontWeight: 600, color: 'var(--color-text-primary)', marginBottom: '12px' }}>Decisions</h2>
      <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', marginBottom: '32px' }}>
        {decisions.length === 0 ? (
          <div className="glass-card" style={{ padding: '30px', textAlign: 'center', color: 'var(--color-text-muted)' }}>No decisions yet.</div>
        ) : decisions.map((d: any, i: number) => (
          <div key={i} className="glass-card" style={{ padding: '16px' }}>
            <p style={{ margin: '0 0 8px', fontWeight: 600, fontSize: '0.9rem' }}>Incident: {d.incident_id}</p>
            <p style={{ margin: '0 0 4px', color: 'var(--color-text-secondary)', fontSize: '0.8rem' }}>{d.rationale}</p>
            <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap', marginTop: '8px' }}>
              {(typeof d.actions_taken === 'string' ? JSON.parse(d.actions_taken) : d.actions_taken || []).map((a: string, j: number) => (
                <span key={j} style={{ background: 'rgba(16, 185, 129, 0.2)', color: '#6ee7b7', padding: '2px 8px', borderRadius: '4px', fontSize: '0.7rem' }}>{a}</span>
              ))}
            </div>
          </div>
        ))}
      </div>

      <h2 style={{ fontSize: '1.1rem', fontWeight: 600, color: 'var(--color-text-primary)', marginBottom: '12px' }}>Proposed Strategies</h2>
      <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
        {strategies.length === 0 ? (
          <div className="glass-card" style={{ padding: '30px', textAlign: 'center', color: 'var(--color-text-muted)' }}>No strategies proposed yet.</div>
        ) : strategies.map((s: any, i: number) => (
          <div key={i} className="glass-card" style={{ padding: '14px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: '0.85rem' }}>{s.agent_name} → {s.incident_id}</span>
            <div style={{ display: 'flex', gap: '16px', fontSize: '0.8rem', color: 'var(--color-text-secondary)' }}>
              <span>Confidence: <strong style={{ color: 'var(--color-accent-cyan)' }}>{((s.confidence || 0) * 100).toFixed(0)}%</strong></span>
              <span>Risk: <strong style={{ color: 'var(--color-accent-amber)' }}>{((s.residual_risk || 0) * 100).toFixed(0)}%</strong></span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
