import type { AuditEvent, BanRecord, GlassBondStore, PathActivity, SecurityMetrics, StoreCounter, TokenBucketResult } from "./types.js";

interface PathWindow {
  expiresAt: number;
  total: number;
  counts: Map<string, number>;
}

interface BucketState {
  tokens: number;
  updatedAt: number;
}

export class MemoryStore implements GlassBondStore {
  private readonly counters = new Map<string, StoreCounter>();
  private readonly bans = new Map<string, BanRecord>();
  private readonly paths = new Map<string, PathWindow>();
  private readonly missing = new Map<string, PathWindow>();
  private readonly buckets = new Map<string, BucketState>();
  private readonly events: AuditEvent[] = [];

  async increment(key: string, windowMs: number): Promise<StoreCounter> {
    const now = Date.now();
    const current = this.counters.get(key);
    if (!current || current.resetAt <= now) {
      const next = { count: 1, resetAt: now + windowMs };
      this.counters.set(key, next);
      return next;
    }
    current.count += 1;
    return current;
  }

  async getCounter(key: string): Promise<StoreCounter | undefined> {
    const current = this.counters.get(key);
    if (!current) return undefined;
    if (current.resetAt <= Date.now()) {
      this.counters.delete(key);
      return undefined;
    }
    return current;
  }

  async setBan(key: string, until: number, reason: string): Promise<void> {
    this.bans.set(key, { until, reason });
  }

  async getBan(key: string): Promise<BanRecord | undefined> {
    const ban = this.bans.get(key);
    if (!ban) return undefined;
    if (ban.until <= Date.now()) {
      this.bans.delete(key);
      return undefined;
    }
    return ban;
  }

  async deleteBan(key: string): Promise<void> {
    this.bans.delete(key);
  }

  async add404(key: string, path: string, windowMs: number): Promise<PathActivity> {
    return this.addToWindow(this.missing, key, path, windowMs);
  }

  async addPath(key: string, path: string, windowMs: number): Promise<PathActivity> {
    return this.addToWindow(this.paths, key, path, windowMs);
  }

  async tokenBucket(key: string, capacity: number, refillPerMs: number): Promise<TokenBucketResult> {
    const now = Date.now();
    const current = this.buckets.get(key) ?? { tokens: capacity, updatedAt: now };
    const elapsed = now - current.updatedAt;
    current.tokens = Math.min(capacity, current.tokens + elapsed * refillPerMs);
    current.updatedAt = now;
    const allowed = current.tokens >= 1;
    if (allowed) current.tokens -= 1;
    this.buckets.set(key, current);
    const needed = Math.max(0, 1 - current.tokens);
    const resetAt = now + Math.ceil(needed / refillPerMs);
    return { allowed, remaining: Math.floor(current.tokens), resetAt };
  }


  async recordEvent(event: AuditEvent): Promise<void> {
    this.events.unshift(event);
    if (this.events.length > 5_000) this.events.length = 5_000;
  }

  async getEvents(limit = 200): Promise<AuditEvent[]> {
    return this.events.slice(0, limit);
  }

  async getMetrics(): Promise<SecurityMetrics> {
    const metrics: SecurityMetrics = {
      totalRequests: this.events.length,
      allowed: 0,
      blocked: 0,
      challenged: 0,
      slowed: 0,
      banned: 0,
      suspicious: 0,
      topThreats: [],
      topIps: [],
      topPaths: [],
      riskBuckets: { low: 0, medium: 0, high: 0, critical: 0 }
    };
    const threatCounts = new Map<string, number>();
    const ipCounts = new Map<string, { count: number; blocked: number }>();
    const pathCounts = new Map<string, { count: number; blocked: number }>();
    for (const event of this.events) {
      if (event.action === "allow") metrics.allowed += 1;
      if (event.action === "block") metrics.blocked += 1;
      if (event.action === "challenge") metrics.challenged += 1;
      if (event.action === "slowdown") metrics.slowed += 1;
      if (event.reasons.some((reason) => reason.includes("ban"))) metrics.banned += 1;
      if (event.score >= 40) metrics.suspicious += 1;
      metrics.riskBuckets[event.level] += 1;
      for (const reason of event.reasons) threatCounts.set(reason, (threatCounts.get(reason) ?? 0) + 1);
      const ip = ipCounts.get(event.ip) ?? { count: 0, blocked: 0 };
      ip.count += 1;
      if (event.action === "block") ip.blocked += 1;
      ipCounts.set(event.ip, ip);
      const path = pathCounts.get(event.path) ?? { count: 0, blocked: 0 };
      path.count += 1;
      if (event.action === "block") path.blocked += 1;
      pathCounts.set(event.path, path);
    }
    metrics.topThreats = [...threatCounts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 10).map(([reason, count]) => ({ reason, count }));
    metrics.topIps = [...ipCounts.entries()].sort((a, b) => b[1].count - a[1].count).slice(0, 10).map(([ip, item]) => ({ ip, count: item.count, blocked: item.blocked }));
    metrics.topPaths = [...pathCounts.entries()].sort((a, b) => b[1].count - a[1].count).slice(0, 10).map(([path, item]) => ({ path, count: item.count, blocked: item.blocked }));
    return metrics;
  }

  private addToWindow(map: Map<string, PathWindow>, key: string, path: string, windowMs: number): PathActivity {
    const now = Date.now();
    const current = map.get(key);
    const window = !current || current.expiresAt <= now ? { expiresAt: now + windowMs, total: 0, counts: new Map<string, number>() } : current;
    window.total += 1;
    window.counts.set(path, (window.counts.get(path) ?? 0) + 1);
    map.set(key, window);
    return { total: window.total, unique: window.counts.size, repeated: (window.counts.get(path) ?? 0) > 3 };
  }
}
