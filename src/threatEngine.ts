import type { GlassBondContext, ThreatResult } from "./types.js";
import { boundedScore, riskLevel } from "./utils.js";

export function evaluateThreat(input: Omit<GlassBondContext, "threat">): ThreatResult {
  const reasons: string[] = [];
  let score = 0;
  const add = (value: number, newReasons: string[]): void => {
    score += value;
    reasons.push(...newReasons);
  };
  add(input.rateLimit.score, input.rateLimit.reasons);
  add(input.userAgent.score * 0.55, input.userAgent.reasons);
  add(input.bot.score, input.bot.reasons);
  add(input.intelligence.score, input.intelligence.reasons);
  add(input.headers.score, input.headers.reasons);
  if (input.honeypot) add(45, ["honeypot route accessed"]);
  if (input.geoBlocked) add(55, ["blocked country"]);
  if (input.ban) add(100, [`temporary ban active: ${input.ban.reason}`]);
  const finalScore = boundedScore(score);
  return { score: finalScore, level: riskLevel(finalScore), reasons: [...new Set(reasons)] };
}
