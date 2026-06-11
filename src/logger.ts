import type { LoggerOptions } from "./types.js";

export type LogLevel = "info" | "warn" | "error";

const colors: Record<LogLevel, string> = { info: "\u001b[36m", warn: "\u001b[33m", error: "\u001b[31m" };
const reset = "\u001b[0m";

export class Logger {
  private readonly options: Required<LoggerOptions>;

  constructor(options: LoggerOptions = {}) {
    this.options = { enabled: options.enabled ?? false, json: options.json ?? false, colors: options.colors ?? true };
  }

  log(level: LogLevel, message: string, meta: Record<string, unknown> = {}): void {
    if (!this.options.enabled) return;
    const entry = { timestamp: new Date().toISOString(), level, message, ...meta };
    if (this.options.json) {
      console.log(JSON.stringify(entry));
      return;
    }
    const prefix = `[${entry.timestamp}] glassbond ${level.toUpperCase()}`;
    const line = `${prefix}: ${message} ${Object.keys(meta).length > 0 ? JSON.stringify(meta) : ""}`.trim();
    console.log(this.options.colors ? `${colors[level]}${line}${reset}` : line);
  }
}
