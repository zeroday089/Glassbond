import { EventEmitter } from "node:events";
import type { GlassBondEventPayload } from "./types.js";

export type GlassBondEventName = "blocked" | "suspicious" | "ban" | "challenge";

export class GlassBondEvents extends EventEmitter {
  on(eventName: GlassBondEventName, listener: (payload: GlassBondEventPayload) => void): this {
    return super.on(eventName, listener);
  }

  emit(eventName: GlassBondEventName, payload: GlassBondEventPayload): boolean {
    return super.emit(eventName, payload);
  }
}

export const events = new GlassBondEvents();
