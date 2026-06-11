import type { BanRecord, GlassBondStore, PathActivity, RedisLikeClient, StoreCounter, TokenBucketResult } from "./types.js";
import { MemoryStore } from "./memoryStore.js";

export class RedisStore implements GlassBondStore {
  private readonly fallback = new MemoryStore();

  constructor(private readonly client: RedisLikeClient, private readonly prefix = "glassbond") {}

  async increment(key: string, windowMs: number): Promise<StoreCounter> {
    const redisKey = this.key("counter", key);
    const now = Date.now();
    const existing = await this.client.get(redisKey);
    const current = existing ? (JSON.parse(existing) as StoreCounter) : undefined;
    const next = !current || current.resetAt <= now ? { count: 1, resetAt: now + windowMs } : { count: current.count + 1, resetAt: current.resetAt };
    await this.client.set(redisKey, JSON.stringify(next), { PX: Math.max(1, next.resetAt - now) });
    return next;
  }

  async getCounter(key: string): Promise<StoreCounter | undefined> {
    const existing = await this.client.get(this.key("counter", key));
    if (!existing) return undefined;
    const counter = JSON.parse(existing) as StoreCounter;
    return counter.resetAt > Date.now() ? counter : undefined;
  }

  async setBan(key: string, until: number, reason: string): Promise<void> {
    await this.client.set(this.key("ban", key), JSON.stringify({ until, reason }), { PX: Math.max(1, until - Date.now()) });
  }

  async getBan(key: string): Promise<BanRecord | undefined> {
    const existing = await this.client.get(this.key("ban", key));
    if (!existing) return undefined;
    const ban = JSON.parse(existing) as BanRecord;
    return ban.until > Date.now() ? ban : undefined;
  }

  async deleteBan(key: string): Promise<void> {
    await this.client.del?.(this.key("ban", key));
  }

  async add404(key: string, path: string, windowMs: number): Promise<PathActivity> {
    return this.fallback.add404(this.key("404", key), path, windowMs);
  }

  async addPath(key: string, path: string, windowMs: number): Promise<PathActivity> {
    return this.fallback.addPath(this.key("path", key), path, windowMs);
  }

  async tokenBucket(key: string, capacity: number, refillPerMs: number): Promise<TokenBucketResult> {
    return this.fallback.tokenBucket(this.key("bucket", key), capacity, refillPerMs);
  }

  private key(...parts: string[]): string {
    return `${this.prefix}:${parts.join(":")}`;
  }
}
