'use client';

import { useEffect, useState } from 'react';

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8080';

export default function IncidentsPage() {
  const [incidents, setIncidents] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchIncidents = async () => {
      try {
        const res = await fetch(`${API_URL}/api/incidents?limit=50`);
        const data = await res.json();
        setIncidents(data.incidents || []);
      } catch { } finally { setLoading(false); }
    };
    fetchIncidents();
    const interval = setInterval(fetchIncidents, 5000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div>
      <h1 style={{ fontSize: '1.5rem', fontWeight: 700, marginBottom: '24px' }}>
        <span className="gradient-text">Incidents</span>
      </h1>

      {loading ? (
        <p style={{ color: 'var(--color-text-muted)' }}>Loading incidents...</p>
      ) : incidents.length === 0 ? (
        <div className="glass-card" style={{ padding: '40px', textAlign: 'center', color: 'var(--color-text-muted)' }}>
          No incidents recorded yet.
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
          {incidents.map((inc: any, i: number) => (
            <div key={i} className="glass-card" style={{ padding: '20px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                  <span className={`badge badge-${inc.severity || 'medium'}`}>{inc.severity}</span>
                  <span style={{ fontWeight: 600, fontSize: '0.95rem' }}>{inc.incident_id}</span>
                </div>
                <span style={{ color: 'var(--color-text-muted)', fontSize: '0.8rem' }}>
                  {inc.attack_class || 'unknown'}
                </span>
              </div>
              <div style={{ display: 'flex', gap: '24px', fontSize: '0.8rem', color: 'var(--color-text-secondary)' }}>
                <span>Confidence: <strong style={{ color: 'var(--color-accent-cyan)' }}>{(inc.confidence * 100).toFixed(0)}%</strong></span>
                <span>Alerts: <strong>{inc.alert_count || 0}</strong></span>
                <span>Kill Chain Phase: <strong>{inc.kill_chain_phase || 0}</strong></span>
                <span>Status: <strong className={inc.status === 'open' ? 'threat-active' : ''} style={{ color: inc.status === 'open' ? 'var(--color-accent-red)' : 'var(--color-accent-green)' }}>{inc.status}</strong></span>
              </div>
              {inc.mitre_techniques && inc.mitre_techniques.length > 0 && (
                <div style={{ marginTop: '8px', display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                  {(typeof inc.mitre_techniques === 'string' ? JSON.parse(inc.mitre_techniques) : inc.mitre_techniques).map((t: string, j: number) => (
                    <span key={j} style={{ background: 'rgba(139, 92, 246, 0.2)', color: '#c4b5fd', padding: '2px 8px', borderRadius: '4px', fontSize: '0.7rem', fontFamily: "'JetBrains Mono', monospace" }}>{t}</span>
                  ))}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
