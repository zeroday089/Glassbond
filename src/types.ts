import type { IncomingMessage, ServerResponse } from "node:http";
import type { GlassBondEvents } from "./events.js";

export type GlassBondMode = "strict" | "balanced" | "api" | "paranoid";
export type DurationString = `${number}${"ms" | "s" | "m" | "h" | "d"}`;
export type RateLimitAlgorithm = "sliding-window" | "token-bucket";
export type RiskLevel = "low" | "medium" | "high" | "critical";
export type GlassBondAction = "allow" | "block" | "challenge" | "slowdown" | "dashboard";
export type JsonObject = Record<string, unknown>;

export interface RateLimitOptions {
  maxRequests: number;
  window: DurationString;
  algorithm?: RateLimitAlgorithm;
  bucketCapacity?: number;
  refillRate?: number;
}

export interface RedisLikeClient {
  get(key: string): Promise<string | null> | string | null;
  set(key: string, value: string, options?: RedisSetOptions): Promise<unknown> | unknown;
  del?(key: string): Promise<unknown> | unknown;
}

export interface RedisSetOptions {
  EX?: number;
  PX?: number;
}

export interface GlassBondStore {
  increment(key: string, windowMs: number): Promise<StoreCounter>;
  getCounter(key: string): Promise<StoreCounter | undefined>;
  setBan(key: string, until: number, reason: string): Promise<void>;
  getBan(key: string): Promise<BanRecord | undefined>;
  deleteBan(key: string): Promise<void>;
  add404(key: string, path: string, windowMs: number): Promise<PathActivity>;
  addPath(key: string, path: string, windowMs: number): Promise<PathActivity>;
  tokenBucket(key: string, capacity: number, refillPerMs: number): Promise<TokenBucketResult>;
  recordEvent?(event: AuditEvent): Promise<void>;
  getEvents?(limit?: number): Promise<AuditEvent[]>;
  getMetrics?(): Promise<SecurityMetrics>;
}

export interface AuditEvent {
  id: string;
  timestamp: string;
  ip: string;
  method: string;
  path: string;
  action: GlassBondAction;
  score: number;
  level: RiskLevel;
  reasons: string[];
  userAgent: string;
  country?: string;
}

export interface SecurityMetrics {
  totalRequests: number;
  allowed: number;
  blocked: number;
  challenged: number;
  slowed: number;
  banned: number;
  suspicious: number;
  topThreats: Array<{ reason: string; count: number }>;
  topIps: Array<{ ip: string; count: number; blocked: number }>;
  topPaths: Array<{ path: string; count: number; blocked: number }>;
  riskBuckets: Record<RiskLevel, number>;
}

export interface StoreCounter {
  count: number;
  resetAt: number;
}

export interface BanRecord {
  until: number;
  reason: string;
}

export interface PathActivity {
  total: number;
  unique: number;
  repeated: boolean;
}

export interface TokenBucketResult {
  allowed: boolean;
  remaining: number;
  resetAt: number;
}

export interface LoggerOptions {
  enabled?: boolean;
  json?: boolean;
  colors?: boolean;
}


export interface DashboardOptions {
  enabled?: boolean;
  path?: string;
  apiKey?: string;
  title?: string;
}

export interface AdvancedProtectionOptions {
  enabled?: boolean;
  credentialStuffingPaths?: string[];
  sensitivePathPatterns?: string[];
  maxUniquePathsPerWindow?: number;
  maxLoginAttemptsPerWindow?: number;
  scanWindow?: DurationString;
}

export interface GlassBondOptions {
  mode?: GlassBondMode;
  rateLimit?: Partial<RateLimitOptions>;
  allowIPs?: string[];
  blockIPs?: string[];
  blockedCountries?: string[];
  banDuration?: DurationString;
  threatThreshold?: number;
  challengeThreshold?: number;
  enableBotDetection?: boolean;
  enableGeoFilter?: boolean;
  enableHoneypot?: boolean;
  enableSlowdown?: boolean;
  slowdownDelays?: number[];
  trustProxy?: boolean;
  store?: GlassBondStore;
  redis?: RedisLikeClient;
  logger?: LoggerOptions;
  challenge?: ChallengeOptions;
  geolocation?: GeoLookup;
  dashboard?: DashboardOptions;
  advanced?: AdvancedProtectionOptions;
}

export interface ChallengeOptions {
  enabled?: boolean;
  headerName?: string;
  token?: string;
}

export type GeoLookup = (ip: string, request: GlassBondRequest) => Promise<string | undefined> | string | undefined;

export interface NormalizedOptions {
  mode: GlassBondMode;
  rateLimit: Required<RateLimitOptions>;
  allowIPs: string[];
  blockIPs: string[];
  blockedCountries: string[];
  banDuration: DurationString;
  threatThreshold: number;
  challengeThreshold: number;
  enableBotDetection: boolean;
  enableGeoFilter: boolean;
  enableHoneypot: boolean;
  enableSlowdown: boolean;
  slowdownDelays: number[];
  trustProxy: boolean;
  store: GlassBondStore;
  logger: Required<LoggerOptions>;
  challenge: Required<ChallengeOptions>;
  geolocation?: GeoLookup;
  dashboard: Required<DashboardOptions>;
  advanced: Required<AdvancedProtectionOptions>;
}

export interface GlassBondRequest {
  method: string;
  url: string;
  path: string;
  headers: Record<string, string | string[] | undefined>;
  ip: string;
  raw: IncomingMessage | Request | unknown;
}

export interface HeaderAnalysis {
  score: number;
  reasons: string[];
}

export interface UserAgentAnalysis {
  userAgent: string;
  score: number;
  reasons: string[];
  isSuspicious: boolean;
  isHeadless: boolean;
}

export interface BotAnalysis {
  score: number;
  reasons: string[];
}

export interface RateLimitResult {
  limited: boolean;
  remaining: number;
  resetAt: number;
  score: number;
  reasons: string[];
}

export interface ThreatResult {
  score: number;
  level: RiskLevel;
  reasons: string[];
}

export interface DecisionResult {
  action: GlassBondAction;
  statusCode: number;
  body: JsonObject;
  delayMs: number;
  threat: ThreatResult;
}

export interface GlassBondContext {
  request: GlassBondRequest;
  options: NormalizedOptions;
  rateLimit: RateLimitResult;
  userAgent: UserAgentAnalysis;
  bot: BotAnalysis;
  headers: HeaderAnalysis;
  honeypot: boolean;
  geoBlocked: boolean;
  country?: string;
  intelligence: BotAnalysis;
  ban?: BanRecord;
  threat: ThreatResult;
}

export interface GlassBondEventPayload {
  ip: string;
  path: string;
  score: number;
  reasons: string[];
  action?: GlassBondAction;
  reason?: string;
}

export interface GlassBondMiddleware {
  (req: IncomingMessage, res: ServerResponse, next?: (error?: Error) => void): void | Promise<void>;
  (instance: FastifyLikeInstance, options: JsonObject, done: (error?: Error) => void): void;
  events: GlassBondEvents;
}

export interface FastifyLikeInstance {
  addHook(name: "onRequest", hook: FastifyHook): void;
}

export type FastifyHook = (request: FastifyRequestLike, reply: FastifyReplyLike) => Promise<void> | void;

export interface FastifyRequestLike {
  raw: IncomingMessage;
}

export interface FastifyReplyLike {
  code(statusCode: number): FastifyReplyLike;
  header(name: string, value: string): FastifyReplyLike;
  send(payload: unknown): void;
}

export type NextMiddleware = (request: Request) => Promise<Response | undefined>;
