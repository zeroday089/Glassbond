import express from "express";
import { glassbond } from "glassbond";

const app = express();
const shield = glassbond({ mode: "balanced" });

shield.events.on("blocked", (event) => console.warn("GlassBond blocked", event));
app.use(shield);
app.get("/", (_req, res) => res.send("Protected by GlassBond"));
app.listen(3000);
