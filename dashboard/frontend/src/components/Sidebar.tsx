"use client";

import React from 'react';

export default function Sidebar() {
  const navItems = [
    { href: '/', label: 'Overview', icon: '🛡️' },
    { href: '/topology', label: 'Network', icon: '🌐' },
    { href: '/incidents', label: 'Incidents', icon: '🚨' },
    { href: '/attacks', label: 'Attacks', icon: '⚔️' },
    { href: '/strategies', label: 'Strategies', icon: '🎯' },
  ];

  return (
    <nav style={{
      width: '240px', background: 'var(--color-bg-secondary)', borderRight: '1px solid var(--color-border)',
      padding: '20px 12px', display: 'flex', flexDirection: 'column', gap: '4px',
    }}>
      <div style={{ padding: '12px 16px', marginBottom: '24px' }}>
        <h1 className="gradient-text" style={{ fontSize: '1.25rem', fontWeight: 700, margin: 0 }}>AMCDS</h1>
        <p style={{ fontSize: '0.7rem', color: 'var(--color-text-muted)', margin: '4px 0 0' }}>Cyber Defense System</p>
      </div>
      {navItems.map(item => (
        <a key={item.href} href={item.href} style={{
          display: 'flex', alignItems: 'center', gap: '12px', padding: '10px 16px', borderRadius: '8px',
          color: 'var(--color-text-secondary)', textDecoration: 'none', fontSize: '0.875rem',
          transition: 'all 0.2s', fontWeight: 500,
        }}
        onMouseEnter={e => { (e.target as HTMLElement).style.background = 'var(--color-bg-card)'; (e.target as HTMLElement).style.color = 'var(--color-text-primary)'; }}
        onMouseLeave={e => { (e.target as HTMLElement).style.background = 'transparent'; (e.target as HTMLElement).style.color = 'var(--color-text-secondary)'; }}
        >
          <span>{item.icon}</span>
          <span>{item.label}</span>
        </a>
      ))}
    </nav>
  );
}
