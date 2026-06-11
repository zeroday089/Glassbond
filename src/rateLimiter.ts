import type { GlassBondRequest, NormalizedOptions, RateLimitResult } from "./types.js";
import { hashKey, parseDuration } from "./utils.js";

export async function checkRateLimit(request: GlassBondRequest, options: NormalizedOptions): Promise<RateLimitResult> {
  const windowMs = parseDuration(options.rateLimit.window);
  const key = hashKey("rate", request.ip);
  if (options.rateLimit.algorithm === "token-bucket") {
    const capacity = options.rateLimit.bucketCapacity;
    const refillRate = options.rateLimit.refillRate;
    const result = await options.store.tokenBucket(key, capacity, refillRate / 1000);
    return {
      limited: !result.allowed,
      remaining: result.remaining,
      resetAt: result.resetAt,
      score: result.allowed ? 0 : 45,
      reasons: result.allowed ? [] : ["too many requests"]
    };
  }
  const counter = await options.store.increment(key, windowMs);
  const remaining = Math.max(0, options.rateLimit.maxRequests - counter.count);
  const limited = counter.count > options.rateLimit.maxRequests;
  const ratio = counter.count / options.rateLimit.maxRequests;
  const score = limited ? 50 : ratio > 0.8 ? 15 : 0;
  return { limited, remaining, resetAt: counter.resetAt, score, reasons: score > 0 ? [limited ? "too many requests" : "approaching rate limit"] : [] };
}
