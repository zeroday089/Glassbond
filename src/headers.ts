import type { GlassBondRequest, HeaderAnalysis } from "./types.js";
import { getHeader } from "./utils.js";

export function analyzeHeaders(request: GlassBondRequest): HeaderAnalysis {
  const reasons: string[] = [];
  let score = 0;
  const host = getHeader(request.headers, "host");
  const accept = getHeader(request.headers, "accept");
  const ua = getHeader(request.headers, "user-agent");
  const connection = getHeader(request.headers, "connection");

  if (!host && !request.url.startsWith("http")) {
    score += 15;
    reasons.push("missing host header");
  }
  if (accept !== undefined && accept.trim() === "") {
    score += 10;
    reasons.push("invalid accept header");
  }
  if (ua !== undefined && ua.trim() === "") {
    score += 20;
    reasons.push("empty user-agent header");
  }
  if (request.method === "GET" && getHeader(request.headers, "content-length")) {
    score += 10;
    reasons.push("unexpected content-length on GET");
  }
  if (connection?.toLowerCase().includes("upgrade") && !getHeader(request.headers, "upgrade")) {
    score += 10;
    reasons.push("invalid upgrade header combination");
  }
  if (!accept && !getHeader(request.headers, "accept-language") && !getHeader(request.headers, "accept-encoding")) {
    score += 10;
    reasons.push("missing browser negotiation headers");
  }
  return { score, reasons };
}
