import "dotenv/config";
import express from "express";
import {
  PORT,
  PUBLIC_URL,
  DISCORD_AUTH_ENABLED,
  TRIAL_HOURS,
  VIP_DISCORD_IDS,
  AUTH_MODE,
} from "./config.js";
import {
  activeClients,
  verifyBitChordAuth,
  requireUserToken,
  trackAddonUser,
  blockIfAuthEnabled,
  registerAuthRoutes,
} from "./auth.js";
import { dashCache, handleSearch, handleIsrc, handleStream } from "./tidal.js";
import { renderDashboard } from "./dashboard.js";

const app = express();
app.use(express.json());

function formatTimeLeft(ms) {
  if (ms <= 0) return "Expired";
  const totalMins = Math.floor(ms / 60000);
  const d = Math.floor(totalMins / 1440);
  const h = Math.floor((totalMins % 1440) / 60);
  const m = totalMins % 60;
  if (d > 0) return `${d}d ${h}h left`;
  if (h > 0) return `${h}h ${m}m left`;
  return `${m}m left`;
}

function handleManifest(req, res) {
  const user = req.addonUser;
  let addonName = "Layz Hi-Res";
  let description = "FLAC · Lossless · Hi-Res";

  if (user) {
    const uname = user.u || "User";
    const isVip = user.vip || VIP_DISCORD_IDS.has(String(user.uid));

    if (isVip) {
      addonName = `${uname} · VIP`;
      description = `${uname} · VIP Permanent · FLAC · Lossless · Hi-Res`;
    } else if (user.exp) {
      const timeLeft = formatTimeLeft(user.exp - Date.now());
      addonName =
        timeLeft === "Expired"
          ? `${uname} · Expired`
          : `${uname} · Trial ${timeLeft}`;
      description = `${uname} · Free Trial ${timeLeft} · FLAC · Lossless · Hi-Res`;
    }
  }

  res.setHeader("Cache-Control", "no-store");
  res.json({
    id: "id.web.layyyz.lzaddon",
    name: addonName,
    version: "1.1.0",
    description,
    resources: ["search", "stream", "isrc"],
    bitchordAuth: AUTH_MODE === "enforce",
    settings: [
      {
        key: "quality",
        type: "select",
        options: [
          { label: "Hi-Res Lossless (24-bit)", value: "hires" },
          { label: "Lossless (16-bit)", value: "lossless" },
          { label: "Dolby Atmos", value: "atmos" },
          { label: "High · 320 kbps", value: "high" },
          { label: "Low · 128 kbps", value: "low" },
        ],
      },
    ],
  });
}

registerAuthRoutes(app);

app.get("/ping", (req, res) => {
  const now = Date.now();
  const activeNow = Array.from(activeClients.values()).filter(
    (ts) => now - ts < 15 * 60 * 1000,
  ).length;

  res.setHeader("Cache-Control", "no-store");
  res.json({
    status: "online",
    uptime: Math.floor(process.uptime()),
    uniqueUsers: activeClients.size,
    activeUsers: activeNow,
    timestamp: now,
  });
});

app.get("/", renderDashboard);

// --- Protected Per-User Routes (/u/:token/...) ---
app.get(
  "/u/:token/manifest.json",
  requireUserToken,
  trackAddonUser,
  handleManifest,
);
app.get(
  "/u/:token/search",
  requireUserToken,
  verifyBitChordAuth,
  trackAddonUser,
  handleSearch,
);
app.get(
  "/u/:token/isrc/:code",
  requireUserToken,
  verifyBitChordAuth,
  trackAddonUser,
  handleIsrc,
);
app.get(
  "/u/:token/stream/:id",
  requireUserToken,
  verifyBitChordAuth,
  trackAddonUser,
  handleStream,
);

// --- Root Routes (Automatically blocked when Discord Auth is enabled) ---
app.get("/manifest.json", blockIfAuthEnabled, trackAddonUser, handleManifest);
app.get(
  "/search",
  blockIfAuthEnabled,
  verifyBitChordAuth,
  trackAddonUser,
  handleSearch,
);
app.get(
  "/isrc/:code",
  blockIfAuthEnabled,
  verifyBitChordAuth,
  trackAddonUser,
  handleIsrc,
);
app.get(
  "/stream/:id",
  blockIfAuthEnabled,
  verifyBitChordAuth,
  trackAddonUser,
  handleStream,
);

app.get("/dash/:token.mpd", (req, res) => {
  const entry = dashCache.get(req.params.token);
  if (!entry || entry.expiresAt < Date.now()) {
    return res.status(404).send("Manifest expired");
  }
  res.setHeader("Content-Type", "application/dash+xml");
  res.send(entry.xml);
});

app.listen(PORT, () => {
  console.log(
    `lz addon running on port ${PORT} (${PUBLIC_URL}) | Discord Auth: ${DISCORD_AUTH_ENABLED ? "ON" : "OFF"} | Trial: ${TRIAL_HOURS}h`,
  );
});
