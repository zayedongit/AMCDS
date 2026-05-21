'use client';

import { useEffect, useRef, useState } from 'react';

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8080';

export default function TopologyPage() {
  const svgRef = useRef<SVGSVGElement>(null);
  const [data, setData] = useState<{ nodes: any[]; edges: any[] }>({ nodes: [], edges: [] });

  useEffect(() => {
    fetch(`${API_URL}/api/topology`)
      .then(r => r.json())
      .then(d => setData(d))
      .catch(e => console.error('Topology fetch error:', e));
  }, []);

  useEffect(() => {
    if (!svgRef.current || data.nodes.length === 0) return;

    const loadD3 = async () => {
      const d3 = await import('d3');
      const svg = d3.select(svgRef.current);
      svg.selectAll('*').remove();

      const width = 900, height = 600;
      svg.attr('viewBox', `0 0 ${width} ${height}`);

      const g = svg.append('g');

      // Zoom
      const zoom = d3.zoom<SVGSVGElement, unknown>()
        .scaleExtent([0.3, 5])
        .on('zoom', (event) => g.attr('transform', event.transform));
      svg.call(zoom);

      const simulation = d3.forceSimulation(data.nodes)
        .force('link', d3.forceLink(data.edges).id((d: any) => d.id).distance(80))
        .force('charge', d3.forceManyBody().strength(-200))
        .force('center', d3.forceCenter(width / 2, height / 2))
        .force('collision', d3.forceCollide(30));

      const link = g.append('g').selectAll('line')
        .data(data.edges).enter().append('line')
        .attr('class', (d: any) => d.type === 'attack' ? 'network-link-attack' : 'network-link')
        .attr('stroke-width', 1);

      const node = g.append('g').selectAll('g')
        .data(data.nodes).enter().append('g')
        .attr('class', 'network-node');

      node.append('circle')
        .attr('r', (d: any) => d.node_type === 'subnet' ? 18 : (d.node_type === 'server' ? 12 : 8))
        .attr('fill', (d: any) => {
          if (d.node_type === 'router') return '#f59e0b';
          if (d.node_type === 'subnet') return '#3b82f6';
          if (d.node_type === 'server') return '#8b5cf6';
          return '#06b6d4';
        })
        .attr('stroke', '#1e293b')
        .attr('stroke-width', 2);

      node.append('text')
        .text((d: any) => d.label || d.id || '')
        .attr('text-anchor', 'middle')
        .attr('dy', 25)
        .attr('fill', '#94a3b8')
        .attr('font-size', '9px');

      simulation.on('tick', () => {
        link.attr('x1', (d: any) => d.source.x).attr('y1', (d: any) => d.source.y)
            .attr('x2', (d: any) => d.target.x).attr('y2', (d: any) => d.target.y);
        node.attr('transform', (d: any) => `translate(${d.x},${d.y})`);
      });
    };

    loadD3();
  }, [data]);

  return (
    <div>
      <h1 style={{ fontSize: '1.5rem', fontWeight: 700, marginBottom: '24px' }}>
        <span className="gradient-text">Network Topology</span>
      </h1>
      <div className="glass-card" style={{ padding: '16px', overflow: 'hidden' }}>
        <svg ref={svgRef} style={{ width: '100%', height: '600px', background: 'var(--color-bg-primary)', borderRadius: '8px' }} />
      </div>
      <div style={{ display: 'flex', gap: '24px', marginTop: '16px', color: 'var(--color-text-muted)', fontSize: '0.8rem' }}>
        <span>🟡 Router</span><span>🔵 Subnet</span><span>🟣 Server</span><span>🔵 Workstation</span>
        <span style={{ color: 'var(--color-accent-red)' }}>━ Attack Path</span>
      </div>
    </div>
  );
}
