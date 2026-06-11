import { normalizeIp } from "./utils.js";

export function isAllowedIp(ip: string, allowIPs: string[]): boolean {
  const normalized = normalizeIp(ip);
  return allowIPs.map(normalizeIp).includes(normalized);
}

export function isBlockedIp(ip: string, blockIPs: string[]): boolean {
  const normalized = normalizeIp(ip);
  return blockIPs.map(normalizeIp).includes(normalized);
}
