import type { BotAnalysis, GlassBondRequest, NormalizedOptions } from "./types.js";
import { getHeader, hashKey, parseDuration } from "./utils.js";

const dangerousExtensions = /\.(?:env|git|bak|old|sql|sqlite|db|config|ini|log|pem|key|yml|yaml|zip|tar|gz)$/iu;
const injectionPattern = /(union\s+select|sleep\s*\(|benchmark\s*\(|<script|\.\.\/|%2e%2e%2f|cmd=|exec=|base64_decode|etc\/passwd)/iu;
const sensitiveDefaults = ["/login", "/signin", "/auth", "/api/login", "/api/auth", "/wp-login.php"];

export async function analyzeAdvancedThreats(request: GlassBondRequest, options: NormalizedOptions): Promise<BotAnalysis> {
  const reasons: string[] = [];
  let score = 0;
  if (!options.advanced.enabled) return { score, reasons };

  const windowMs = parseDuration(options.advanced.scanWindow);
  const pathActivity = await options.store.addPath(hashKey("advanced:path", request.ip), request.path, windowMs);
  if (pathActivity.unique >= options.advanced.maxUniquePathsPerWindow) {
    score += 30;
    reasons.push("advanced reconnaissance burst");
  }

  if (dangerousExtensions.test(request.path)) {
    score += 25;
    reasons.push("sensitive file discovery attempt");
  }
  if (injectionPattern.test(request.url)) {
    score += 35;
    reasons.push("injection payload detected");
  }
  if (isCredentialStuffingTarget(request.path, options.advanced.credentialStuffingPaths)) {
    const loginCounter = await options.store.increment(hashKey("advanced:login", request.ip, request.path), windowMs);
    if (loginCounter.count > options.advanced.maxLoginAttemptsPerWindow) {
      score += 45;
      reasons.push("credential stuffing pattern");
    }
  }
  if (matchesSensitivePattern(request.path, options.advanced.sensitivePathPatterns)) {
    score += 20;
    reasons.push("sensitive endpoint probing");
  }

  const fingerprint = [getHeader(request.headers, "accept"), getHeader(request.headers, "accept-language"), getHeader(request.headers, "accept-encoding")].filter(Boolean).join("|");
  if (fingerprint.length < 8) {
    score += 10;
    reasons.push("weak client fingerprint");
  }

  return { score: Math.min(100, score), reasons: [...new Set(reasons)] };
}

function isCredentialStuffingTarget(path: string, configured: string[]): boolean {
  const candidates = configured.length > 0 ? configured : sensitiveDefaults;
  return candidates.some((candidate) => path === candidate || path.startsWith(`${candidate}/`));
}

function matchesSensitivePattern(path: string, patterns: string[]): boolean {
  return patterns.some((pattern) => path.includes(pattern));
}
