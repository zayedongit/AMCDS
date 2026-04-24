'use client';

import { useEffect, useState } from 'react';

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8080';

interface SimStats {
  total_alerts: number;
  total_incidents: number;
  open_incidents: number;
  redis_keys: number;
}

export default function DashboardPage() {
  const [stats, setStats] = useState<SimStats>({ total_alerts: 0, total_incidents: 0, open_incidents: 0, redis_keys: 0 });
  const [alerts, setAlerts] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [statusRes, alertsRes] = await Promise.all([
          fetch(`${API_URL}/api/simulation/status`).then(r => r.json()).catch(() => ({ stats: {} })),
          fetch(`${API_URL}/api/alerts?limit=10`).then(r => r.json()).catch(() => ({ alerts: [] })),
        ]);
        setStats(statusRes.stats || {});
        setAlerts(alertsRes.alerts || []);
      } catch (e) {
        console.error('Failed to fetch dashboard data:', e);
      } finally {
        setLoading(false);
      }
    };
    fetchData();
    const interval = setInterval(fetchData, 5000);
    return () => clearInterval(interval);
  }, []);

  const metricCards = [
    { label: 'Total Alerts', value: stats.total_alerts || 0, color: 'var(--color-accent-amber)', icon: '⚡' },
    { label: 'Active Incidents', value: stats.open_incidents || 0, color: 'var(--color-accent-red)', icon: '🔥' },
    { label: 'Total Incidents', value: stats.total_incidents || 0, color: 'var(--color-accent-blue)', icon: '📊' },
    { label: 'Agent Cache Keys', value: stats.redis_keys || 0, color: 'var(--color-accent-green)', icon: '🔑' },
  ];

  return (
    <div>
      <header style={{ marginBottom: '32px' }}>
        <h1 style={{ fontSize: '1.75rem', fontWeight: 700, margin: '0 0 4px' }}>
          <span className="gradient-text">Cyber Defense Dashboard</span>
        </h1>
        <p style={{ color: 'var(--color-text-muted)', fontSize: '0.875rem', margin: 0 }}>
          Real-time monitoring • Autonomous response • Full simulation
        </p>
      </header>

      {/* Metrics Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '16px', marginBottom: '32px' }}>
        {metricCards.map((card, i) => (
          <div key={i} className="glass-card" style={{ padding: '20px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
              <div>
                <p style={{ color: 'var(--color-text-muted)', fontSize: '0.75rem', margin: '0 0 8px', textTransform: 'uppercase', letterSpacing: '0.05em' }}>{card.label}</p>
                <p style={{ fontSize: '2rem', fontWeight: 700, margin: 0, color: card.color, fontFamily: "'JetBrains Mono', monospace" }}>
                  {loading ? '...' : card.value.toLocaleString()}
                </p>
              </div>
              <span style={{ fontSize: '1.5rem' }}>{card.icon}</span>
            </div>
          </div>
        ))}
      </div>

      {/* Recent Alerts */}
      <div className="glass-card" style={{ padding: '24px' }}>
        <h2 style={{ fontSize: '1.1rem', fontWeight: 600, margin: '0 0 16px', color: 'var(--color-text-primary)' }}>
          Recent Alerts
        </h2>
        {alerts.length === 0 ? (
          <p style={{ color: 'var(--color-text-muted)', textAlign: 'center', padding: '40px 0' }}>
            {loading ? 'Loading...' : 'No alerts yet. Simulation may still be starting.'}
          </p>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
            {alerts.map((alert: any, i: number) => (
              <div key={i} style={{
                display: 'flex', alignItems: 'center', gap: '12px', padding: '12px 16px',
                background: 'var(--color-bg-primary)', borderRadius: '8px', fontSize: '0.85rem',
              }}>
                <span className={`badge badge-${alert.severity || 'medium'}`}>{alert.severity || 'med'}</span>
                <span style={{ flex: 1, color: 'var(--color-text-primary)' }}>{alert.description || alert.alert_type}</span>
                <span style={{ color: 'var(--color-text-muted)', fontFamily: "'JetBrains Mono', monospace", fontSize: '0.75rem' }}>
                  {alert.mitre_technique || ''}
                </span>
                <span style={{ color: 'var(--color-text-muted)', fontSize: '0.75rem' }}>{alert.agent_name}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
