/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * React Flow edge that renders the normal connection plus light particles that travel along the path
 * when the edge is "pulsed" (a matched live request). Uses requestAnimationFrame + SVGPathElement
 * getPointAtLength for buttery-smooth particle motion instead of SMIL <animateMotion> which is
 * unreliable in dynamically-added elements.
 */
import React, { useEffect, useRef, useState, useCallback } from 'react';
import { BaseEdge, EdgeProps, getBezierPath } from '@xyflow/react';
import { subscribePulse, Pulse } from '../../utils/trafficViz';

// Offscreen SVG path element used to sample coordinates via getPointAtLength.
// Created once lazily and reused by every Particle — much cheaper than creating one per particle.
let _measurer: SVGPathElement | null = null;
function getMeasurer(): SVGPathElement {
  if (!_measurer) {
    const ns = 'http://www.w3.org/2000/svg';
    const svg = document.createElementNS(ns, 'svg');
    svg.setAttribute('style', 'position:absolute;width:0;height:0;overflow:hidden;pointer-events:none');
    svg.setAttribute('aria-hidden', 'true');
    _measurer = document.createElementNS(ns, 'path') as SVGPathElement;
    svg.appendChild(_measurer);
    document.body.appendChild(svg);
  }
  return _measurer;
}

interface ActiveParticle extends Pulse {
  startTime: number;
}

/** A single glowing particle that travels from source to target using rAF path sampling. */
const Particle: React.FC<{ path: string; color: string; durationMs: number; onDone: () => void }> = ({
  path, color, durationMs, onDone,
}) => {
  const circleRef = useRef<SVGCircleElement>(null);
  const trailRef = useRef<SVGCircleElement>(null);
  const trail2Ref = useRef<SVGCircleElement>(null);

  useEffect(() => {
    const measurer = getMeasurer();
    measurer.setAttribute('d', path);
    const totalLen = measurer.getTotalLength();
    if (totalLen === 0) { onDone(); return; }

    let raf: number;
    const start = performance.now();

    const tick = (now: number) => {
      const elapsed = now - start;
      const t = Math.min(elapsed / durationMs, 1);

      // Ease-out cubic for a nice deceleration
      const eased = 1 - Math.pow(1 - t, 3);
      const pt = measurer.getPointAtLength(eased * totalLen);

      // Leading particle
      if (circleRef.current) {
        circleRef.current.setAttribute('cx', String(pt.x));
        circleRef.current.setAttribute('cy', String(pt.y));
        circleRef.current.setAttribute('opacity', String(t < 0.9 ? 0.95 : (1 - t) * 9.5));
      }

      // Trail particle 1 (slightly behind)
      const t1 = Math.max(0, eased - 0.06);
      const pt1 = measurer.getPointAtLength(t1 * totalLen);
      if (trailRef.current) {
        trailRef.current.setAttribute('cx', String(pt1.x));
        trailRef.current.setAttribute('cy', String(pt1.y));
        trailRef.current.setAttribute('opacity', String(Math.max(0, (t < 0.85 ? 0.5 : (1 - t) * 3.4))));
      }

      // Trail particle 2 (further behind)
      const t2 = Math.max(0, eased - 0.14);
      const pt2 = measurer.getPointAtLength(t2 * totalLen);
      if (trail2Ref.current) {
        trail2Ref.current.setAttribute('cx', String(pt2.x));
        trail2Ref.current.setAttribute('cy', String(pt2.y));
        trail2Ref.current.setAttribute('opacity', String(Math.max(0, (t < 0.8 ? 0.25 : (1 - t) * 1.7))));
      }

      if (t < 1) {
        raf = requestAnimationFrame(tick);
      } else {
        onDone();
      }
    };

    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [path, durationMs, onDone]);

  return (
    <g>
      {/* Outermost trail (large, faint glow) */}
      <circle ref={trail2Ref} r={3} fill={color} opacity={0} style={{ filter: `drop-shadow(0 0 3px ${color})` }} />
      {/* Inner trail */}
      <circle ref={trailRef} r={4} fill={color} opacity={0} style={{ filter: `drop-shadow(0 0 4px ${color})` }} />
      {/* Leading bright particle */}
      <circle ref={circleRef} r={5} fill={color} opacity={0} style={{ filter: `drop-shadow(0 0 6px ${color}) drop-shadow(0 0 10px ${color})` }} />
    </g>
  );
};

export const TrafficEdge: React.FC<EdgeProps> = (props) => {
  const { id, sourceX, sourceY, targetX, targetY, sourcePosition, targetPosition, markerEnd, style } = props;
  const [edgePath] = getBezierPath({ sourceX, sourceY, sourcePosition, targetX, targetY, targetPosition });
  const [particles, setParticles] = useState<ActiveParticle[]>([]);

  const removeParticle = useCallback((pid: string) => {
    setParticles(prev => prev.filter(x => x.id !== pid));
  }, []);

  useEffect(() => {
    return subscribePulse(id, (p) => {
      setParticles(prev => [...prev, { ...p, startTime: performance.now() }]);
    });
  }, [id]);

  return (
    <>
      <BaseEdge id={id} path={edgePath} markerEnd={markerEnd} style={style} />
      {particles.map(p => (
        <Particle
          key={p.id}
          path={edgePath}
          color={p.color}
          durationMs={p.durationMs}
          onDone={() => removeParticle(p.id)}
        />
      ))}
    </>
  );
};
