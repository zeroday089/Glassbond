import { createHash, timingSafeEqual } from "node:crypto";
import type { DurationString, GlassBondRequest } from "./types.js";

const durationPattern = /^(\d+)(ms|s|m|h|d)$/u;

export function parseDuration(value: DurationString): number {
  const match = durationPattern.exec(value);
  if (!match) throw new Error(`Invalid duration: ${value}`);
  const amount = Number(match[1]);
  const unit = match[2] ?? "ms";
  const multipliers: Record<string, number> = { ms: 1, s: 1_000, m: 60_000, h: 3_600_000, d: 86_400_000 };
  return amount * (multipliers[unit] ?? 1);
}

export function normalizeIp(ip: string): string {
  const value = ip.trim();
  if (value.startsWith("::ffff:")) return value.slice(7);
  if (value === "::1") return "127.0.0.1";
  return value;
}

export function getHeader(headers: Record<string, string | string[] | undefined>, name: string): string | undefined {
  const direct = headers[name] ?? headers[name.toLowerCase()];
  if (Array.isArray(direct)) return direct.join(",");
  return direct;
}

export function requestPath(url: string): string {
  try {
    return new URL(url, "http://glassbond.local").pathname;
  } catch {
    return "/";
  }
}

export function extractIp(req: { socket?: { remoteAddress?: string }; headers?: Record<string, string | string[] | undefined> }, trustProxy: boolean): string {
  if (trustProxy) {
    const forwarded = getHeader(req.headers ?? {}, "x-forwarded-for");
    if (forwarded) return normalizeIp(forwarded.split(",")[0]?.trim() ?? forwarded);
    const realIp = getHeader(req.headers ?? {}, "x-real-ip");
    if (realIp) return normalizeIp(realIp);
  }
  return normalizeIp(req.socket?.remoteAddress ?? "0.0.0.0");
}

export function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export function unique<T>(values: T[]): T[] {
  return [...new Set(values)];
}

export function boundedScore(score: number): number {
  return Math.max(0, Math.min(100, Math.round(score)));
}

export function riskLevel(score: number): "low" | "medium" | "high" | "critical" {
  if (score >= 90) return "critical";
  if (score >= 70) return "high";
  if (score >= 40) return "medium";
  return "low";
}

export function hashKey(...parts: string[]): string {
  return createHash("sha256").update(parts.join(":"), "utf8").digest("hex");
}

export function safeEqual(left: string, right: string): boolean {
  const a = Buffer.from(left);
  const b = Buffer.from(right);
  return a.length === b.length && timingSafeEqual(a, b);
}

export function createRequestFromFetch(request: Request): GlassBondRequest {
  const headers: Record<string, string> = {};
  request.headers.forEach((value, key) => {
    headers[key] = value;
  });
  const ip = headers["x-forwarded-for"]?.split(",")[0]?.trim() ?? headers["x-real-ip"] ?? "0.0.0.0";
  return { method: request.method, url: request.url, path: requestPath(request.url), headers, ip: normalizeIp(ip), raw: request };
}
