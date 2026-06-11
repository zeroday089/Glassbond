declare module "node:events" {
  export class EventEmitter {
    on(eventName: string, listener: unknown): this;
    emit(eventName: string, ...args: unknown[]): boolean;
  }
}

declare module "node:http" {
  export class IncomingMessage {
    constructor(socket?: unknown);
    url?: string;
    method?: string;
    headers: Record<string, string | string[] | undefined>;
    socket: { remoteAddress?: string };
  }

  export class ServerResponse<Request extends IncomingMessage = IncomingMessage> {
    constructor(request?: Request);
    statusCode: number;
    setHeader(name: string, value: string | number | string[]): void;
    end(chunk?: string | Uint8Array): void;
  }
}

declare module "node:crypto" {
  export function createHash(algorithm: string): { update(data: string, encoding?: string): { digest(encoding: "hex"): string } };
  export function timingSafeEqual(left: Uint8Array, right: Uint8Array): boolean;
}

declare module "vitest" {
  export function describe(name: string, callback: () => void): void;
  export function it(name: string, callback: () => void | Promise<void>): void;
  export const expect: (value: unknown) => {
    toBe(expected: unknown): void;
    toContain(expected: unknown): void;
    toBeGreaterThan(expected: number): void;
    toBeGreaterThanOrEqual(expected: number): void;
    toHaveBeenCalled(): void;
    toHaveBeenCalledOnce(): void;
  };
  export const vi: { fn<T extends (...args: unknown[]) => unknown = (...args: unknown[]) => unknown>(implementation?: T): T & { mock: unknown } };
}

declare const Buffer: {
  from(value: string | Uint8Array): Uint8Array & { toString(encoding?: string): string };
  isBuffer(value: unknown): value is Uint8Array;
};
