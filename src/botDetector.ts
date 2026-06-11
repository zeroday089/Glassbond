import type { BotAnalysis, GlassBondRequest, NormalizedOptions, UserAgentAnalysis } from "./types.js";
import { getHeader, hashKey, parseDuration } from "./utils.js";

export async function analyzeBot(request: GlassBondRequest, userAgent: UserAgentAnalysis, options: NormalizedOptions): Promise<BotAnalysis> {
  const reasons: string[] = [];
  let score = 0;
  if (!options.enableBotDetection) return { score, reasons };

  if (userAgent.isSuspicious) {
    score += Math.min(35, userAgent.score / 2);
    reasons.push(...userAgent.reasons);
  }
  if (!getHeader(request.headers, "accept") || !getHeader(request.headers, "accept-language")) {
    score += 10;
    reasons.push("missing common browser headers");
  }
  if (userAgent.isHeadless) {
    score += 25;
    reasons.push("headless browser");
  }

  const activity = await options.store.addPath(hashKey("paths", request.ip), request.path, parseDuration("5m"));
  if (activity.unique >= 20) {
    score += 25;
    reasons.push("high path enumeration");
  }
  if (activity.repeated) {
    score += 10;
    reasons.push("repeated path probing");
  }
  return { score: Math.min(100, Math.round(score)), reasons: [...new Set(reasons)] };
}
