import type { IncomingMessage, ServerResponse } from "node:http";
import { events as defaultEvents, GlassBondEvents } from "./events.js";
import { analyzeBot } from "./botDetector.js";
import { challengeBody, shouldChallenge, verifyChallenge } from "./challenge.js";
import { isDashboardPath, renderDashboard } from "./dashboard.js";
import { analyzeHeaders } from "./headers.js";
import { isHoneypotPath } from "./honeypot.js";
import { isAllowedIp, isBlockedIp } from "./ipFilter.js";
import { analyzeAdvancedThreats } from "./intelligence.js";
import { Logger } from "./logger.js";
import { MemoryStore } from "./memoryStore.js";
import { checkRateLimit } from "./rateLimiter.js";
import { RedisStore } from "./redisStore.js";
import { evaluateThreat } from "./threatEngine.js";
import type { DecisionResult, FastifyLikeInstance, GlassBondContext, GlassBondMiddleware, GlassBondOptions, GlassBondRequest, NextMiddleware, NormalizedOptions } from "./types.js";
import { analyzeUserAgent } from "./userAgentDetector.js";
import { createRequestFromFetch, extractIp, getHeader, hashKey, parseDuration, requestPath, sleep } from "./utils.js";

const presets: Record<string, Partial<NormalizedOptions>> = {
  balanced: { threatThreshold: 70, challengeThreshold: 55, enableSlowdown: true, enableBotDetection: true, enableGeoFilter: false, enableHoneypot: true },
  strict: { threatThreshold: 60, challengeThreshold: 45, enableSlowdown: false, enableBotDetection: true, enableGeoFilter: true, enableHoneypot: true },
  api: { threatThreshold: 75, challengeThreshold: 65, enableSlowdown: false, enableBotDetection: true, enableGeoFilter: false, enableHoneypot: true },
  paranoid: { threatThreshold: 45, challengeThreshold: 35, enableSlowdown: false, enableBotDetection: true, enableGeoFilter: true, enableHoneypot: true }
};

export function normalizeOptions(options: GlassBondOptions = {}): NormalizedOptions {
  const mode = options.mode ?? "balanced";
  const preset = presets[mode] ?? presets.balanced ?? {};
  const rateLimit = {
    maxRequests: options.rateLimit?.maxRequests ?? 100,
    window: options.rateLimit?.window ?? "1m",
    algorithm: options.rateLimit?.algorithm ?? "sliding-window",
    bucketCapacity: options.rateLimit?.bucketCapacity ?? options.rateLimit?.maxRequests ?? 100,
    refillRate: options.rateLimit?.refillRate ?? ((options.rateLimit?.maxRequests ?? 100) / (parseDuration(options.rateLimit?.window ?? "1m") / 1000))
  } as const;
  return {
    mode,
    rateLimit,
    allowIPs: options.allowIPs ?? [],
    blockIPs: options.blockIPs ?? [],
    blockedCountries: options.blockedCountries ?? [],
    banDuration: options.banDuration ?? "1h",
    threatThreshold: options.threatThreshold ?? preset.threatThreshold ?? 70,
    challengeThreshold: options.challengeThreshold ?? preset.challengeThreshold ?? 55,
    enableBotDetection: options.enableBotDetection ?? preset.enableBotDetection ?? true,
    enableGeoFilter: options.enableGeoFilter ?? preset.enableGeoFilter ?? false,
    enableHoneypot: options.enableHoneypot ?? preset.enableHoneypot ?? true,
    enableSlowdown: options.enableSlowdown ?? preset.enableSlowdown ?? true,
    slowdownDelays: options.slowdownDelays ?? [500, 1000, 2000, 5000],
    trustProxy: options.trustProxy ?? true,
    store: options.store ?? (options.redis ? new RedisStore(options.redis) : new MemoryStore()),
    logger: { enabled: options.logger?.enabled ?? false, json: options.logger?.json ?? false, colors: options.logger?.colors ?? true },
    challenge: { enabled: options.challenge?.enabled ?? false, headerName: options.challenge?.headerName ?? "x-glassbond-challenge", token: options.challenge?.token ?? "" },
    dashboard: { enabled: options.dashboard?.enabled ?? false, path: options.dashboard?.path ?? "/__glassbond", apiKey: options.dashboard?.apiKey ?? "", title: options.dashboard?.title ?? "GlassBond Security Dashboard" },
    advanced: { enabled: options.advanced?.enabled ?? true, credentialStuffingPaths: options.advanced?.credentialStuffingPaths ?? [], sensitivePathPatterns: options.advanced?.sensitivePathPatterns ?? ["/.git", "/.env", "/admin", "/backup", "/config"], maxUniquePathsPerWindow: options.advanced?.maxUniquePathsPerWindow ?? 25, maxLoginAttemptsPerWindow: options.advanced?.maxLoginAttemptsPerWindow ?? 8, scanWindow: options.advanced?.scanWindow ?? "5m" },
    ...(options.geolocation ? { geolocation: options.geolocation } : {})
  };
}

export function createRequest(req: IncomingMessage, options: NormalizedOptions): GlassBondRequest {
  const headers = req.headers;
  const url = req.url ?? "/";
  return { method: req.method ?? "GET", url, path: requestPath(url), headers, ip: extractIp(req, options.trustProxy), raw: req };
}

export async function inspectRequest(request: GlassBondRequest, options: NormalizedOptions): Promise<GlassBondContext> {
  if (isAllowedIp(request.ip, options.allowIPs)) {
    const rateLimit = { limited: false, remaining: options.rateLimit.maxRequests, resetAt: Date.now(), score: 0, reasons: [] };
    const userAgent = { userAgent: getHeader(request.headers, "user-agent") ?? "", score: 0, reasons: [], isSuspicious: false, isHeadless: false };
    const bot = { score: 0, reasons: [] };
    const intelligence = { score: 0, reasons: [] };
    const headers = { score: 0, reasons: [] };
    const threat = { score: 0, level: "low" as const, reasons: [] };
    return { request, options, rateLimit, userAgent, bot, intelligence, headers, honeypot: false, geoBlocked: false, threat };
  }
  const ban = await options.store.getBan(hashKey("ban", request.ip));
  const userAgent = analyzeUserAgent(request);
  const headers = analyzeHeaders(request);
  const rateLimit = await checkRateLimit(request, options);
  const bot = await analyzeBot(request, userAgent, options);
  const intelligence = await analyzeAdvancedThreats(request, options);
  const honeypot = options.enableHoneypot && isHoneypotPath(request.path);
  const country = options.enableGeoFilter && options.geolocation ? await options.geolocation(request.ip, request) : undefined;
  const geoBlocked = country ? options.blockedCountries.map((value) => value.toUpperCase()).includes(country.toUpperCase()) : false;
  const withoutThreat = { request, options, rateLimit, userAgent, bot, intelligence, headers, honeypot, geoBlocked, ...(country ? { country } : {}), ...(ban ? { ban } : {}) };
  const threat = evaluateThreat(withoutThreat);
  return { ...withoutThreat, threat };
}

export async function decide(context: GlassBondContext, eventBus: GlassBondEvents = defaultEvents): Promise<DecisionResult> {
  const { request, options, threat } = context;
  if (isAllowedIp(request.ip, options.allowIPs)) return decision("allow", 200, {}, 0, threat);
  if (isBlockedIp(request.ip, options.blockIPs)) return block(context, eventBus, "blocked ip");
  if (context.ban) return block(context, eventBus, context.ban.reason);
  if (context.geoBlocked) return block(context, eventBus, "blocked country");
  if (context.rateLimit.limited || threat.score >= options.threatThreshold) {
    const repeatedKey = hashKey("abuse", request.ip);
    const abuse = await options.store.increment(repeatedKey, parseDuration("24h"));
    const banMs = escalateBanDuration(options.banDuration, abuse.count);
    await options.store.setBan(hashKey("ban", request.ip), Date.now() + banMs, threat.reasons[0] ?? "abuse detected");
    eventBus.emit("ban", payload(context, "block", "temporary ban issued"));
    return block(context, eventBus, "request blocked by GlassBond");
  }
  if (shouldChallenge(threat, options.challengeThreshold, options.challenge) && !verifyChallenge(request, options.challenge)) {
    eventBus.emit("challenge", payload(context, "challenge", "challenge required"));
    return decision("challenge", 403, challengeBody(), 0, threat);
  }
  if (threat.score >= 40) eventBus.emit("suspicious", payload(context, "allow", "suspicious request"));
  if (options.enableSlowdown && threat.score >= 40) {
    const index = Math.min(options.slowdownDelays.length - 1, Math.floor((threat.score - 40) / 15));
    return decision("slowdown", 200, {}, options.slowdownDelays[index] ?? 500, threat);
  }
  return decision("allow", 200, {}, 0, threat);
}

export function glassbond(options: GlassBondOptions = {}): GlassBondMiddleware {
  const normalized = normalizeOptions(options);
  const logger = new Logger(normalized.logger);
  const eventBus = new GlassBondEvents();

  const handler = ((first: IncomingMessage | FastifyLikeInstance, second: ServerResponse | Record<string, unknown>, third?: ((error?: Error) => void)) => {
    if (isFastifyInstance(first) && typeof third === "function") {
      first.addHook("onRequest", async (request, reply) => {
        const glassBondRequest = createRequest(request.raw, normalized);
        if (isDashboardPath(glassBondRequest.path, normalized)) {
          const dashboard = await renderDashboard(normalized, glassBondRequest.url, getHeader(glassBondRequest.headers, "authorization"));
          reply.code(dashboard.status).header("content-type", dashboard.contentType).send(dashboard.body);
          return;
        }
        const context = await inspectRequest(glassBondRequest, normalized);
        const result = await decide(context, eventBus);
        await recordAudit(context, result);
        if (result.delayMs > 0) await sleep(result.delayMs);
        if (result.action !== "allow" && result.action !== "slowdown") {
          reply.code(result.statusCode).header("content-type", "application/json").send(result.body);
        }
      });
      third();
      return;
    }
    void handleNode(first as IncomingMessage, second as ServerResponse, third, normalized, eventBus, logger);
  }) as GlassBondMiddleware;

  handler.events = eventBus;
  return handler;
}

export function createNextMiddleware(options: GlassBondOptions = {}): NextMiddleware {
  const normalized = normalizeOptions(options);
  const eventBus = new GlassBondEvents();
  return async (request: Request): Promise<Response | undefined> => {
    const glassBondRequest = createRequestFromFetch(request);
    if (isDashboardPath(glassBondRequest.path, normalized)) {
      const dashboard = await renderDashboard(normalized, glassBondRequest.url, getHeader(glassBondRequest.headers, "authorization"));
      return new Response(dashboard.body, { status: dashboard.status, headers: { "content-type": dashboard.contentType } });
    }
    const context = await inspectRequest(glassBondRequest, normalized);
    const result = await decide(context, eventBus);
    await recordAudit(context, result);
    if (result.delayMs > 0) await sleep(result.delayMs);
    if (result.action === "allow" || result.action === "slowdown") return undefined;
    return Response.json(result.body, { status: result.statusCode, headers: { "x-glassbond-score": String(result.threat.score) } });
  };
}

async function handleNode(req: IncomingMessage, res: ServerResponse, next: ((error?: Error) => void) | undefined, options: NormalizedOptions, eventBus: GlassBondEvents, logger: Logger): Promise<void> {
  try {
    const glassBondRequest = createRequest(req, options);
    if (isDashboardPath(glassBondRequest.path, options)) {
      const dashboard = await renderDashboard(options, glassBondRequest.url, getHeader(glassBondRequest.headers, "authorization"));
      res.statusCode = dashboard.status;
      res.setHeader("content-type", dashboard.contentType);
      res.end(dashboard.body);
      return;
    }
    const context = await inspectRequest(glassBondRequest, options);
    const result = await decide(context, eventBus);
    await recordAudit(context, result);
    res.setHeader("x-glassbond-score", String(result.threat.score));
    res.setHeader("x-glassbond-action", result.action);
    if (result.delayMs > 0) await sleep(result.delayMs);
    if (result.action === "allow" || result.action === "slowdown") {
      next?.();
      return;
    }
    logger.log("warn", "request blocked", { ip: context.request.ip, path: context.request.path, score: result.threat.score });
    res.statusCode = result.statusCode;
    res.setHeader("content-type", "application/json; charset=utf-8");
    res.end(JSON.stringify(result.body));
  } catch (error) {
    next?.(error instanceof Error ? error : new Error("GlassBond failed"));
  }
}

async function recordAudit(context: GlassBondContext, result: DecisionResult): Promise<void> {
  await context.options.store.recordEvent?.({
    id: hashKey(String(Date.now()), context.request.ip, context.request.path, String(Math.random())),
    timestamp: new Date().toISOString(),
    ip: context.request.ip,
    method: context.request.method,
    path: context.request.path,
    action: result.action,
    score: result.threat.score,
    level: result.threat.level,
    reasons: result.threat.reasons,
    userAgent: context.userAgent.userAgent,
    ...(context.country ? { country: context.country } : {})
  });
}

function block(context: GlassBondContext, eventBus: GlassBondEvents, reason: string): DecisionResult {
  eventBus.emit("blocked", payload(context, "block", reason));
  return decision("block", 403, { error: "forbidden", message: "Request blocked by GlassBond.", score: context.threat.score, reasons: context.threat.reasons }, 0, context.threat);
}

function decision(action: DecisionResult["action"], statusCode: number, body: Record<string, unknown>, delayMs: number, threat: DecisionResult["threat"]): DecisionResult {
  return { action, statusCode, body, delayMs, threat };
}

function payload(context: GlassBondContext, action: DecisionResult["action"], reason: string): { ip: string; path: string; score: number; reasons: string[]; action: DecisionResult["action"]; reason: string } {
  return { ip: context.request.ip, path: context.request.path, score: context.threat.score, reasons: context.threat.reasons, action, reason };
}

function isFastifyInstance(value: IncomingMessage | FastifyLikeInstance): value is FastifyLikeInstance {
  return typeof (value as FastifyLikeInstance).addHook === "function" && !getHeader((value as IncomingMessage).headers ?? {}, "host");
}

function escalateBanDuration(base: `${number}${"ms" | "s" | "m" | "h" | "d"}`, count: number): number {
  const durations = [parseDuration("5m"), parseDuration("30m"), parseDuration("1h"), parseDuration("24h")];
  if (count <= 1) return parseDuration(base);
  return durations[Math.min(durations.length - 1, count - 1)] ?? durations[0] ?? 300_000;
}
