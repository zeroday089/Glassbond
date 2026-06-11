# GlassBond

**Application-layer protection for modern web applications and APIs.**

GlassBond is a TypeScript middleware package for Express, Fastify, Next.js, NestJS, and raw Node HTTP servers. It evaluates each request through an application-layer security pipeline:

```text
Request → IP Filter → Rate Limiter → Bot Detector → Threat Score Engine → Challenge Engine → Decision Engine → Application
```

## Installation

```bash
npm install glassbond
```

## Quick Start

```ts
import express from "express";
import { glassbond } from "glassbond";

const app = express();

app.use(glassbond());
app.get("/", (_req, res) => res.send("protected"));
```

## Configuration

```ts
app.use(
  glassbond({
    mode: "strict",
    rateLimit: { maxRequests: 100, window: "1m" },
    allowIPs: ["192.168.1.5", "10.0.0.4"],
    blockIPs: ["1.2.3.4"],
    blockedCountries: ["RU", "KP"],
    banDuration: "1h",
    threatThreshold: 70,
    enableBotDetection: true,
    enableGeoFilter: true,
    enableHoneypot: true,
    enableSlowdown: true
  })
);
```

## Express Example

```ts
import express from "express";
import { glassbond } from "glassbond";

const app = express();
const shield = glassbond({ mode: "balanced" });

shield.events.on("blocked", (event) => {
  console.warn("blocked", event);
});

app.use(shield);
app.listen(3000);
```

## Fastify Example

```ts
import Fastify from "fastify";
import { glassbond } from "glassbond";

const fastify = Fastify();
fastify.register(glassbond({ mode: "api" }));
await fastify.listen({ port: 3000 });
```

## Next.js Example

Create `middleware.ts`:

```ts
export { createNextMiddleware as middleware } from "glassbond";

export const config = { matcher: ["/:path*"] };
```

For custom options:

```ts
import { createNextMiddleware } from "glassbond";

export const middleware = createNextMiddleware({ mode: "strict" });
```

## Options

| Option | Description | Default |
| --- | --- | --- |
| `mode` | `strict`, `balanced`, `api`, or `paranoid` preset. | `balanced` |
| `rateLimit.maxRequests` | Requests allowed per window. | `100` |
| `rateLimit.window` | Duration such as `1s`, `1m`, `1h`. | `1m` |
| `rateLimit.algorithm` | `sliding-window` or `token-bucket`. | `sliding-window` |
| `allowIPs` | Trusted IPs that bypass decisions. | `[]` |
| `blockIPs` | IPs that are always blocked. | `[]` |
| `blockedCountries` | ISO country codes blocked when a geolocation function is provided. | `[]` |
| `banDuration` | Initial temporary ban duration. | `1h` |
| `threatThreshold` | Score at which requests are blocked. | preset dependent |
| `challengeThreshold` | Score at which challenge is required. | preset dependent |
| `enableBotDetection` | Enables bot heuristics. | `true` |
| `enableGeoFilter` | Enables country filtering. | preset dependent |
| `enableHoneypot` | Enables honeypot route scoring. | `true` |
| `enableSlowdown` | Delays suspicious requests instead of immediately blocking lower risk traffic. | `true` |
| `redis` | Redis-like client for distributed counters and bans. | unset |
| `store` | Custom `GlassBondStore`. | `MemoryStore` |

## Events

```ts
const shield = glassbond();
shield.events.on("blocked", console.log);
shield.events.on("suspicious", console.log);
shield.events.on("ban", console.log);
shield.events.on("challenge", console.log);
```

## Rate Limiting

GlassBond supports per-second, per-minute, and per-hour limits through duration windows. The default algorithm is sliding window. Token bucket can be enabled for burst-tolerant APIs:

```ts
glassbond({
  rateLimit: {
    algorithm: "token-bucket",
    maxRequests: 100,
    window: "1m",
    bucketCapacity: 200,
    refillRate: 100
  }
});
```

## Bot Detection

GlassBond scores suspicious clients using user-agent signatures, missing headers, header anomalies, request frequency, 404 enumeration, repeated paths, headless browsers, and honeypot hits. Built-in user-agent detections include `sqlmap`, `nikto`, `masscan`, `curl`, `wget`, `python-requests`, `go-http-client`, Headless Chrome, PhantomJS, empty user agents, and unknown user agents.

## Threat Scores

Threat scores are normalized from `0` to `100`:

- `low`: 0-39
- `medium`: 40-69
- `high`: 70-89
- `critical`: 90-100

Example result from `inspectRequest`:

```ts
{
  score: 82,
  level: "high",
  reasons: ["too many requests", "headless browser", "multiple 404 scans"]
}
```

## Redis

Provide any Redis-like client with `get`, `set`, and optional `del` methods:

```ts
import { createClient } from "redis";
import { glassbond } from "glassbond";

const redis = createClient();
await redis.connect();

app.use(glassbond({ redis }));
```

## Presets

- `balanced`: general web application protection.
- `strict`: lower thresholds and geofilter-ready defaults.
- `api`: API-friendly thresholds.
- `paranoid`: aggressive blocking for high-risk surfaces.

## API Reference

### `glassbond(options?)`

Returns a hybrid middleware/plugin function for Express, Fastify, NestJS Express adapters, and raw Node HTTP flows.

### `createNextMiddleware(options?)`

Returns a Next.js-compatible middleware function that responds with JSON on blocked or challenged requests.

### `MemoryStore`

Default in-process store for counters, bans, path activity, and token buckets.

### `RedisStore`

Distributed counter/ban store backed by a Redis-like client. Path activity and token buckets use an in-process fallback unless a custom store is supplied.

## Build

```bash
npm run build
```

The package emits ESM, CommonJS, and TypeScript declarations in `dist/`, ready for `npm publish`.
