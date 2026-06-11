import { describe, expect, it, vi } from "vitest";
import type { IncomingMessage, ServerResponse } from "node:http";
import { analyzeHeaders, analyzeUserAgent, createNextMiddleware, glassbond, honeypotRoutes, inspectRequest, MemoryStore, normalizeOptions } from "../src/index.js";
import type { FastifyHook, FastifyLikeInstance, FastifyReplyLike } from "../src/index.js";
import { isHoneypotPath } from "../src/honeypot.js";
import { parseDuration } from "../src/utils.js";

interface MockResponse {
  statusCode: number;
  body: string;
  headers: Record<string, string | number | string[]>;
  setHeader(name: string, value: string | number | string[]): void;
  end(chunk?: string | Uint8Array): void;
}

function request(headers: Record<string, string> = {}, url = "/", ip = "203.0.113.9"): IncomingMessage {
  return { url, method: "GET", headers, socket: { remoteAddress: ip } } as unknown as IncomingMessage;
}

function response(): MockResponse & ServerResponse {
  const res: MockResponse = {
    statusCode: 200,
    body: "",
    headers: {},
    setHeader(name, value) {
      this.headers[name.toLowerCase()] = value;
    },
    end(chunk) {
      if (typeof chunk === "string") this.body += chunk;
      if (chunk instanceof Uint8Array) this.body += Buffer.from(chunk).toString("utf8");
    }
  };
  return res as MockResponse & ServerResponse;
}

describe("GlassBond", () => {
  it("parses durations", () => {
    expect(parseDuration("1m")).toBe(60_000);
    expect(parseDuration("2h")).toBe(7_200_000);
  });

  it("detects suspicious user agents", () => {
    const analysis = analyzeUserAgent({ method: "GET", url: "/", path: "/", ip: "1.1.1.1", headers: { "user-agent": "sqlmap" }, raw: {} });
    expect(analysis.score).toBeGreaterThanOrEqual(80);
    expect(analysis.reasons).toContain("sqlmap scanner");
  });

  it("detects header anomalies", () => {
    const analysis = analyzeHeaders({ method: "GET", url: "/", path: "/", ip: "1.1.1.1", headers: { accept: "", "user-agent": "" }, raw: {} });
    expect(analysis.reasons).toContain("invalid accept header");
    expect(analysis.reasons).toContain("empty user-agent header");
  });

  it("matches honeypot routes", () => {
    expect(honeypotRoutes).toContain("/.env");
    expect(isHoneypotPath("/.git/config")).toBe(true);
    expect(isHoneypotPath("/health")).toBe(false);
  });

  it("bypasses checks for allowlisted IPs", async () => {
    const options = normalizeOptions({ allowIPs: ["203.0.113.9"], rateLimit: { maxRequests: 1, window: "1m" } });
    const ctx = await inspectRequest({ method: "GET", url: "/", path: "/", ip: "203.0.113.9", headers: { "user-agent": "sqlmap" }, raw: {} }, options);
    expect(ctx.threat.score).toBe(0);
  });

  it("blocks honeypot scanner and emits events", async () => {
    const middleware = glassbond({ enableSlowdown: false, logger: { enabled: false } });
    const blocked = vi.fn();
    middleware.events.on("blocked", blocked);
    const req = request({ host: "example.com", "user-agent": "sqlmap" }, "/.env");
    const res = response();
    await middleware(req, res, vi.fn());
    expect(res.statusCode).toBe(403);
    expect(blocked).toHaveBeenCalledOnce();
  });

  it("rate limits excessive requests", async () => {
    const middleware = glassbond({ enableSlowdown: false, rateLimit: { maxRequests: 1, window: "1m" } });
    const headers = { host: "example.com", "user-agent": "Mozilla/5.0", accept: "*/*", "accept-language": "en" };
    await middleware(request(headers), response(), vi.fn());
    const res = response();
    await middleware(request(headers), res, vi.fn());
    expect(res.statusCode).toBe(403);
  });

  it("supports token bucket store", async () => {
    const store = new MemoryStore();
    const first = await store.tokenBucket("k", 1, 0.0001);
    const second = await store.tokenBucket("k", 1, 0.0001);
    expect(first.allowed).toBe(true);
    expect(second.allowed).toBe(false);
  });

  it("supports Next.js middleware", async () => {
    const middleware = createNextMiddleware({ enableSlowdown: false, threatThreshold: 50 });
    const result = await middleware(new Request("https://example.com/.env", { headers: { "user-agent": "sqlmap" } }));
    expect(result?.status).toBe(403);
  });


  it("serves the dashboard and metrics API", async () => {
    const middleware = glassbond({ dashboard: { enabled: true, apiKey: "secret" }, enableSlowdown: false });
    await middleware(request({ host: "example.com", "user-agent": "sqlmap" }, "/.env"), response(), vi.fn());
    const unauthorized = response();
    await middleware(request({ host: "example.com" }, "/__glassbond"), unauthorized, vi.fn());
    expect(unauthorized.statusCode).toBe(401);
    const dashboard = response();
    await middleware(request({ host: "example.com", authorization: "Bearer secret" }, "/__glassbond"), dashboard, vi.fn());
    expect(dashboard.body).toContain("GlassBond Command Center");
    const api = response();
    await middleware(request({ host: "example.com", authorization: "Bearer secret" }, "/__glassbond/api"), api, vi.fn());
    expect(api.body).toContain("totalRequests");
  });

  it("detects advanced credential stuffing and injection signals", async () => {
    const options = normalizeOptions({ advanced: { maxLoginAttemptsPerWindow: 1 }, enableSlowdown: false, threatThreshold: 40 });
    const first = await inspectRequest({ method: "POST", url: "/login?next=/", path: "/login", ip: "198.51.100.7", headers: { host: "example.com", "user-agent": "Mozilla/5.0" }, raw: {} }, options);
    const second = await inspectRequest({ method: "POST", url: "/login?id=1 UNION SELECT password", path: "/login", ip: "198.51.100.7", headers: { host: "example.com", "user-agent": "Mozilla/5.0" }, raw: {} }, options);
    expect(first.threat.score).toBeGreaterThan(0);
    expect(second.threat.reasons).toContain("credential stuffing pattern");
    expect(second.threat.reasons).toContain("injection payload detected");
  });

  it("registers as a Fastify plugin", async () => {
    let hook: FastifyHook | undefined;
    const instance: FastifyLikeInstance = { addHook: (_name: "onRequest", fn: FastifyHook) => { hook = fn; } };
    const done = vi.fn();
    const middleware = glassbond({ threatThreshold: 50 });
    middleware(instance, {}, done);
    expect(done).toHaveBeenCalledOnce();
    const reply: FastifyReplyLike = { code: vi.fn(() => reply), header: vi.fn(() => reply), send: vi.fn() };
    await hook?.({ raw: request({ "user-agent": "sqlmap" }, "/.env") }, reply);
    expect(reply.send).toHaveBeenCalled();
  });
});
