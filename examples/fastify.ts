import Fastify from "fastify";
import { glassbond } from "glassbond";

const fastify = Fastify();
fastify.register(glassbond({ mode: "api" }));
fastify.get("/", async () => ({ ok: true }));
await fastify.listen({ port: 3000 });
