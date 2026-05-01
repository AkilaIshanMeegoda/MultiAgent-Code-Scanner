import { FileCode, Bug, FileText, ShieldAlert, CheckCircle2, XCircle } from 'lucide-react';

// ── Constants ────────────────────────────────────────────────────────────────

/** Map SSE / pipelineSteps keys (PascalCase) → graph node IDs (snake_case) */
const AGENT_TO_NODE = {
  OrchestratorAgent:  'orchestrator',
  VulnerabilityAgent: 'vulnerability_agent',
  CodeQualityAgent:   'code_quality_agent',
  ReportAgent:        'report_agent',
};

const NW = 160, NH = 54, HW = NW / 2, HH = NH / 2;
const W = 460, H = 460;

const NODES = [
  { id: 'orchestrator',        label: 'Orchestrator',  x: 200, y: 75,  Icon: FileCode    },
  { id: 'vulnerability_agent', label: 'Vulnerability', x: 200, y: 190, Icon: ShieldAlert },
  { id: 'code_quality_agent',  label: 'Code Quality',  x: 200, y: 305, Icon: Bug         },
  { id: 'report_agent',        label: 'Report',        x: 200, y: 420, Icon: FileText    },
];

/**
 * Main edges: the sequential full-audit path.
 * Bypass edges: conditional shortcuts when an agent is skipped.
 *   skipNode = the node that is skipped when this bypass is taken.
 */
const MAIN_EDGES = [
  { id: 'e_o_v', from: 'orchestrator',        to: 'vulnerability_agent' },
  { id: 'e_v_q', from: 'vulnerability_agent',  to: 'code_quality_agent'  },
  { id: 'e_q_r', from: 'code_quality_agent',   to: 'report_agent'        },
];

const BYPASS_EDGES = [
  // quality/performance scope: orchestrator skips vulnerability → goes to code_quality
  { id: 'e_o_q', from: 'orchestrator',        to: 'code_quality_agent', skipNode: 'vulnerability_agent' },
  // security scope: vulnerability skips code_quality → goes to report
  { id: 'e_v_r', from: 'vulnerability_agent', to: 'report_agent',       skipNode: 'code_quality_agent'  },
];

// ── Style palettes ───────────────────────────────────────────────────────────

const NODE_STYLE = {
  waiting:  { border: '#2d3f54', bg: '#111d2b', fg: '#4a6278' },
  active:   { border: '#3b82f6', bg: '#0e2a4a', fg: '#93c5fd' },
  complete: { border: '#10b981', bg: '#062820', fg: '#34d399' },
  error:    { border: '#ef4444', bg: '#290a0a', fg: '#fca5a5' },
  skipped:  { border: '#1e2d3d', bg: '#0a1422', fg: '#2c4056' },
};

const EDGE_COLOR = {
  waiting: '#2a3d52',
  flowing: '#3b82f6',
  done:    '#10b981',
  skipped: '#1a2535',
};

// ── Path helpers ──────────────────────────────────────────────────────────────

function straightPath(fromId, toId) {
  const f = NODES.find(n => n.id === fromId);
  const t = NODES.find(n => n.id === toId);
  if (!f || !t) return '';
  return `M ${f.x},${f.y + HH} L ${t.x},${t.y - HH}`;
}

/**
 * Curved bypass path that arcs to the right of the nodes.
 * Control points at x+135 produce a smooth S-curve that visually
 * jumps over any intermediate skipped nodes.
 */
function bypassPath(fromId, toId) {
  const f = NODES.find(n => n.id === fromId);
  const t = NODES.find(n => n.id === toId);
  if (!f || !t) return '';
  const fy = f.y + HH;
  const ty = t.y - HH;
  const cp = f.x + 135;
  return `M ${f.x},${fy} C ${cp},${fy} ${cp},${ty} ${t.x},${ty}`;
}

// ── Component ────────────────────────────────────────────────────────────────

export default function FlowGraph({ pipelineSteps = {} }) {
  const nodeStatus = {};
  NODES.forEach(n => {
    const key = Object.keys(AGENT_TO_NODE).find(k => AGENT_TO_NODE[k] === n.id);
    nodeStatus[n.id] = (key && pipelineSteps[key]) || 'waiting';
  });

  function mainEdgeState(edge) {
    const fs = nodeStatus[edge.from];
    const ts = nodeStatus[edge.to];
    if (fs === 'skipped' || ts === 'skipped') return 'skipped';
    if (fs === 'complete' || fs === 'error')  return 'done';
    if (fs === 'active')                       return 'flowing';
    return 'waiting';
  }

  function bypassEdgeState(edge) {
    if (nodeStatus[edge.skipNode] !== 'skipped') return 'hidden';
    const fs = nodeStatus[edge.from];
    const ts = nodeStatus[edge.to];
    if (fs === 'complete' || fs === 'error') {
      return (ts === 'active') ? 'flowing' : 'done';
    }
    if (fs === 'active') return 'flowing';
    return 'waiting';
  }

  return (
    <div className="flow-graph-wrap">
      {/* Legend */}
      <div className="flow-legend">
        <span className="flow-legend-item">
          <span className="flow-legend-dot" style={{ background: '#3b82f6' }} /> Running
        </span>
        <span className="flow-legend-item">
          <span className="flow-legend-dot" style={{ background: '#10b981' }} /> Done
        </span>
        <span className="flow-legend-item">
          <span className="flow-legend-dot" style={{ background: '#ef4444' }} /> Error
        </span>
        <span className="flow-legend-item">
          <span className="flow-legend-dot waiting" /> Waiting
        </span>
        <span className="flow-legend-item">
          <span className="flow-legend-line dashed" /> Skipped
        </span>
      </div>

      {/* Graph canvas */}
      <div className="flow-graph-canvas" style={{ width: W, height: H, position: 'relative' }}>

        <svg
          viewBox={`0 0 ${W} ${H}`}
          width={W}
          height={H}
          style={{ position: 'absolute', inset: 0, pointerEvents: 'none', overflow: 'visible' }}
        >
          <defs>
            {['waiting', 'flowing', 'done', 'skipped'].map(s => (
              <marker
                key={s}
                id={`ah-${s}`}
                markerWidth="8" markerHeight="8"
                refX="7" refY="3"
                orient="auto"
              >
                <path d="M 0,0 L 0,6 L 8,3 z" fill={EDGE_COLOR[s]} />
              </marker>
            ))}
          </defs>

          {/* Main sequential edges */}
          {MAIN_EDGES.map(edge => {
            const es    = mainEdgeState(edge);
            const color = EDGE_COLOR[es];
            return (
              <path
                key={edge.id}
                d={straightPath(edge.from, edge.to)}
                fill="none"
                stroke={color}
                strokeWidth={es === 'flowing' || es === 'done' ? 2.5 : 1.5}
                strokeOpacity={es === 'skipped' ? 0.2 : 1}
                markerEnd={`url(#ah-${es})`}
                style={{ transition: 'stroke 0.5s ease, stroke-opacity 0.4s ease' }}
              />
            );
          })}

          {/* Bypass edges — dashed arcs on the right, visible only when the bypass is taken */}
          {BYPASS_EDGES.map(edge => {
            const bs = bypassEdgeState(edge);
            if (bs === 'hidden') return null;
            const color = bs === 'done'    ? EDGE_COLOR.done
                        : bs === 'flowing' ? EDGE_COLOR.flowing
                        : EDGE_COLOR.waiting;
            const mk = bs === 'done' ? 'done' : bs === 'flowing' ? 'flowing' : 'waiting';
            return (
              <path
                key={edge.id}
                d={bypassPath(edge.from, edge.to)}
                fill="none"
                stroke={color}
                strokeWidth={2}
                strokeDasharray="6 3"
                markerEnd={`url(#ah-${mk})`}
                style={{ transition: 'stroke 0.5s ease' }}
              />
            );
          })}
        </svg>

        {/* Node boxes */}
        {NODES.map(node => {
          const status   = nodeStatus[node.id] || 'waiting';
          const style    = NODE_STYLE[status];
          const { Icon } = node;
          const isActive = status === 'active';

          return (
            <div
              key={node.id}
              className={`flow-node${isActive ? ' flow-node-active' : ''}`}
              style={{
                left:        node.x - HW,
                top:         node.y - HH,
                width:       NW,
                height:      NH,
                borderColor: style.border,
                background:  style.bg,
                color:       style.fg,
                boxShadow:   isActive ? `0 0 18px ${style.border}88` : 'none',
                opacity:     status === 'skipped' ? 0.3 : 1,
                transition:  'opacity 0.4s ease, box-shadow 0.3s ease',
              }}
            >
              {isActive
                ? <span className="spinner" style={{ width: 13, height: 13, borderWidth: 2, flexShrink: 0 }} />
                : status === 'complete'
                  ? <CheckCircle2 size={13} style={{ flexShrink: 0 }} />
                  : status === 'error'
                    ? <XCircle size={13} style={{ flexShrink: 0 }} />
                    : <Icon size={13} style={{ flexShrink: 0 }} />
              }
              <span className="flow-node-label">{node.label}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
