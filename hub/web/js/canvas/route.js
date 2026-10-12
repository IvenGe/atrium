/** Edge paths. Primary edges use a cubic; gutters use an orthogonal track. */

function num(value) {
  return Number.isFinite(value) ? value : 0;
}

export function cubic(x1, y1, x2, y2) {
  x1 = num(x1); y1 = num(y1); x2 = num(x2); y2 = num(y2);
  const dx = Math.max(40, Math.abs(x2 - x1) * 0.45);
  const dir = x2 >= x1 ? 1 : -1;
  return `M${x1},${y1} C${x1 + dir * dx},${y1} ${x2 - dir * dx},${y2} ${x2},${y2}`;
}

export function gutter(x1, y1, x2, y2, track = 0) {
  x1 = num(x1); y1 = num(y1); x2 = num(x2); y2 = num(y2);
  const mid = (x1 + x2) / 2 + num(track) * 14;
  return `M${x1},${y1} H${mid} V${y2} H${x2}`;
}

export function labelAnchor(x1, y1, x2, y2) {
  return { x: (num(x1) + num(x2)) / 2, y: (num(y1) + num(y2)) / 2 };
}

/** Assign a small integer track so edges that share a gutter do not sit on the same line. */
export function tracks(edges) {
  const used = new Map();
  const out = new Map();
  for (const edge of edges || []) {
    const key = [edge.source, edge.target].sort().join("|");
    const n = used.get(key) || 0;
    used.set(key, n + 1);
    out.set(edge.id, n - Math.floor((used.get(key) - 1) / 2));
  }
  return out;
}
