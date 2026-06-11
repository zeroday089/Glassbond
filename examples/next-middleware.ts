import { createNextMiddleware } from "glassbond";

export const middleware = createNextMiddleware({ mode: "strict" });
export const config = { matcher: ["/:path*"] };
