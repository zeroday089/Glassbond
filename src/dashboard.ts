import type { AuditEvent, NormalizedOptions, SecurityMetrics } from "./types.js";
import { safeEqual } from "./utils.js";

export interface DashboardResponse {
  status: number;
  contentType: string;
  body: string;
}

export async function renderDashboard(options: NormalizedOptions, url: string, authorization?: string): Promise<DashboardResponse> {
  if (!isAuthorized(options.dashboard.apiKey, authorization)) {
    return { status: 401, contentType: "application/json; charset=utf-8", body: JSON.stringify({ error: "unauthorized" }) };
  }
  const parsed = new URL(url, "http://glassbond.local");
  const events = await options.store.getEvents?.(200) ?? [];
  const metrics = await options.store.getMetrics?.() ?? emptyMetrics();
  if (parsed.pathname.endsWith("/api")) {
    return { status: 200, contentType: "application/json; charset=utf-8", body: JSON.stringify({ metrics, events }) };
  }
  return { status: 200, contentType: "text/html; charset=utf-8", body: html(options.dashboard.title, metrics, events) };
}

export function isDashboardPath(path: string, options: NormalizedOptions): boolean {
  return options.dashboard.enabled && (path === options.dashboard.path || path === `${options.dashboard.path}/api`);
}

function isAuthorized(apiKey: string, authorization?: string): boolean {
  if (!apiKey) return true;
  const token = authorization?.replace(/^Bearer\s+/iu, "") ?? "";
  return token.length > 0 && safeEqual(token, apiKey);
}

function emptyMetrics(): SecurityMetrics {
  return { totalRequests: 0, allowed: 0, blocked: 0, challenged: 0, slowed: 0, banned: 0, suspicious: 0, topThreats: [], topIps: [], topPaths: [], riskBuckets: { low: 0, medium: 0, high: 0, critical: 0 } };
}

function html(title: string, metrics: SecurityMetrics, events: AuditEvent[]): string {
  const rows = events.map((event) => `<tr><td>${escapeHtml(event.timestamp)}</td><td>${escapeHtml(event.ip)}</td><td>${escapeHtml(event.method)}</td><td>${escapeHtml(event.path)}</td><td><span class="pill ${event.action}">${event.action}</span></td><td>${event.score}</td><td>${escapeHtml(event.reasons.join(", "))}</td></tr>`).join("");
  const threats = metrics.topThreats.map((item) => `<li>${escapeHtml(item.reason)} <b>${item.count}</b></li>`).join("");
  const ips = metrics.topIps.map((item) => `<li>${escapeHtml(item.ip)} <b>${item.count}</b> req / <b>${item.blocked}</b> blocked</li>`).join("");
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${escapeHtml(title)}</title><style>${css()}</style></head><body><main><section class="hero"><div><p class="eyebrow">GlassBond Command Center</p><h1>${escapeHtml(title)}</h1><p>Live application-layer security telemetry, abuse decisions, threat reasons, IP activity, and route intelligence.</p></div><div class="score">${metrics.blocked}<span>blocked</span></div></section><section class="grid"><article><span>Total</span><b>${metrics.totalRequests}</b></article><article><span>Allowed</span><b>${metrics.allowed}</b></article><article><span>Slowed</span><b>${metrics.slowed}</b></article><article><span>Challenged</span><b>${metrics.challenged}</b></article><article><span>Banned</span><b>${metrics.banned}</b></article><article><span>Suspicious</span><b>${metrics.suspicious}</b></article></section><section class="columns"><article><h2>Top threats</h2><ul>${threats || "<li>No threats yet</li>"}</ul></article><article><h2>Top IPs</h2><ul>${ips || "<li>No IP activity yet</li>"}</ul></article></section><section class="panel"><h2>Recent events</h2><table><thead><tr><th>Time</th><th>IP</th><th>Method</th><th>Path</th><th>Action</th><th>Score</th><th>Reasons</th></tr></thead><tbody>${rows}</tbody></table></section></main></body></html>`;
}

function css(): string {
  return "body{margin:0;background:#08111f;color:#eaf2ff;font-family:Inter,system-ui,sans-serif}main{max-width:1200px;margin:auto;padding:32px}.hero{display:flex;justify-content:space-between;gap:24px;padding:32px;border:1px solid #214166;border-radius:28px;background:linear-gradient(135deg,#10233d,#0d1728)}.eyebrow{color:#68e1fd;text-transform:uppercase;letter-spacing:.18em}.score{font-size:64px;font-weight:800;color:#ff6b6b}.score span{display:block;font-size:14px;color:#b9c9dc}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:16px;margin:24px 0}.grid article,.panel,.columns article{background:#0d1a2d;border:1px solid #203b5e;border-radius:20px;padding:20px}.grid span{display:block;color:#93a8c0}.grid b{font-size:34px}.columns{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:16px;margin-bottom:24px}table{width:100%;border-collapse:collapse}th,td{padding:12px;border-bottom:1px solid #203b5e;text-align:left}th{color:#93a8c0}.pill{border-radius:999px;padding:4px 10px;background:#203b5e}.block{background:#7f1d1d}.allow{background:#14532d}.slowdown{background:#854d0e}.challenge{background:#5b21b6}";
}

function escapeHtml(value: string): string {
  return value.replace(/[&<>"]/gu, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[char] ?? char);
}
