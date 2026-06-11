import type { GlassBondRequest, UserAgentAnalysis } from "./types.js";
import { getHeader } from "./utils.js";

const signatures: Array<{ pattern: RegExp; score: number; reason: string; headless?: boolean }> = [
  { pattern: /sqlmap/iu, score: 80, reason: "sqlmap scanner" },
  { pattern: /nikto/iu, score: 75, reason: "nikto scanner" },
  { pattern: /masscan/iu, score: 80, reason: "masscan scanner" },
  { pattern: /curl/iu, score: 30, reason: "curl user-agent" },
  { pattern: /wget/iu, score: 35, reason: "wget user-agent" },
  { pattern: /python-requests|aiohttp|urllib/iu, score: 45, reason: "python requests user-agent" },
  { pattern: /go-http-client/iu, score: 40, reason: "go-http-client user-agent" },
  { pattern: /headlesschrome/iu, score: 65, reason: "headless browser", headless: true },
  { pattern: /phantomjs/iu, score: 70, reason: "phantomjs headless browser", headless: true },
  { pattern: /scrapy|crawler|spider|bot/iu, score: 35, reason: "crawler user-agent" }
];

export function analyzeUserAgent(request: GlassBondRequest): UserAgentAnalysis {
  const userAgent = getHeader(request.headers, "user-agent") ?? "";
  const reasons: string[] = [];
  let score = 0;
  let isHeadless = false;
  if (userAgent.trim() === "") {
    score += 55;
    reasons.push("empty user-agent");
  }
  for (const signature of signatures) {
    if (signature.pattern.test(userAgent)) {
      score += signature.score;
      reasons.push(signature.reason);
      isHeadless = isHeadless || signature.headless === true;
    }
  }
  if (userAgent && !/(mozilla|chrome|safari|firefox|edge|opera|curl|wget|postman|insomnia|node|python|go-http-client)/iu.test(userAgent)) {
    score += 20;
    reasons.push("unknown user-agent");
  }
  return { userAgent, score: Math.min(100, score), reasons, isSuspicious: score >= 30, isHeadless };
}
