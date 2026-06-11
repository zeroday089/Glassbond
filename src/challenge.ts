import type { ChallengeOptions, GlassBondRequest, ThreatResult } from "./types.js";
import { getHeader, safeEqual } from "./utils.js";

export function shouldChallenge(threat: ThreatResult, threshold: number, options: ChallengeOptions): boolean {
  return options.enabled === true && threat.score >= threshold;
}

export function verifyChallenge(request: GlassBondRequest, options: ChallengeOptions): boolean {
  if (options.enabled !== true) return true;
  if (!options.token) return false;
  const headerName = options.headerName ?? "x-glassbond-challenge";
  const provided = getHeader(request.headers, headerName);
  return provided ? safeEqual(provided, options.token) : false;
}

export function challengeBody(): Record<string, unknown> {
  return { error: "challenge_required", message: "Additional verification is required by GlassBond." };
}
