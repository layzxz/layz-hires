import {
  PUBLIC_URL,
  DISCORD_AUTH_ENABLED,
  TRIAL_HOURS,
  VIP_DISCORD_IDS,
  verifySignedPayload,
  parseCookies,
  escapeHtml,
} from "./config.js";

export function renderDashboard(req, res) {
  const cookies = parseCookies(req);
  const session = cookies.lz_session
    ? verifySignedPayload(cookies.lz_session)
    : null;

  const isVip = session
    ? session.vip || VIP_DISCORD_IDS.has(session.uid)
    : false;
  const isExpired =
    session && !isVip && session.exp && Date.now() > session.exp;
  const manifestUrl = session
    ? `${PUBLIC_URL}/u/${session.t}/manifest.json`
    : `${PUBLIC_URL}/manifest.json`;

  let accessSectionHtml = "";
  if (!DISCORD_AUTH_ENABLED) {
    accessSectionHtml = `
    <div class="section-label">Manifest URL</div>
    <div class="url-box">
      <span class="url-text" id="manifestUrl">${manifestUrl}</span>
      <button class="btn-copy" id="copyBtn" onclick="copyManifest()">Copy URL</button>
    </div>`;
  } else if (!session) {
    accessSectionHtml = `
    <div class="section-label">Access Required · ${TRIAL_HOURS}h Trial</div>
    <a href="/auth/discord" class="btn-discord">
      <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor">
        <path d="M20.317 4.37a19.791 19.791 0 0 0-4.885-1.515.074.074 0 0 0-.079.037c-.21.375-.444.864-.608 1.25a18.27 18.27 0 0 0-5.487 0 12.64 12.64 0 0 0-.617-1.25.077.077 0 0 0-.079-.037A19.736 19.736 0 0 0 3.677 4.37a.07.07 0 0 0-.032.027C.533 9.046-.32 13.58.099 18.057a.082.082 0 0 0 .031.057 19.9 19.9 0 0 0 5.993 3.03.078.078 0 0 0 .084-.028c.462-.63.874-1.295 1.226-1.994.021-.041.001-.09-.041-.106a13.107 13.107 0 0 1-1.872-.892.077.077 0 0 1-.008-.128 10.2 10.2 0 0 0 .372-.292.074.074 0 0 1 .077-.01c3.928 1.793 8.18 1.793 12.062 0a.074.074 0 0 1 .078.01c.12.098.246.198.373.292a.077.077 0 0 1-.006.127 12.299 12.299 0 0 1-1.873.892.077.077 0 0 0-.041.107c.36.698.772 1.362 1.225 1.993a.076.076 0 0 0 .084.028 19.839 19.839 0 0 0 6.002-3.03.077.077 0 0 0 .032-.054c.5-5.177-.838-9.674-3.549-13.66a.061.061 0 0 0-.031-.028zM8.02 15.33c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.956-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.956 2.418-2.157 2.418zm7.975 0c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.955-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.946 2.418-2.157 2.418z"/>
      </svg>
      <span>Login with Discord to Generate URL</span>
    </a>`;
  } else {
    const badgeHtml = isVip
      ? `<span class="tier-pill vip">VIP · Permanent</span>`
      : isExpired
        ? `<span class="tier-pill expired">Trial Expired</span>`
        : `<span class="tier-pill trial" id="trialCountdown" data-exp="${session.exp}">Trial · Counting...</span>`;

    accessSectionHtml = `
    <div class="user-card">
      <div class="user-info">
        <img class="user-avatar" src="${escapeHtml(session.av)}" alt="Avatar" />
        <div>
          <div class="user-name">${escapeHtml(session.u)}</div>
          ${badgeHtml}
        </div>
      </div>
      <a href="/logout" class="btn-logout">Logout</a>
    </div>
    <div class="section-label">Personal Manifest URL</div>
    ${
      isExpired
        ? `<div class="expired-box">Your ${TRIAL_HOURS}-hour trial has ended. Contact the owner to upgrade to permanent access.</div>`
        : `<div class="url-box">
      <span class="url-text" id="manifestUrl">${manifestUrl}</span>
      <button class="btn-copy" id="copyBtn" onclick="copyManifest()">Copy URL</button>
    </div>`
    }`;
  }

  const adminUsersSectionHtml = isVip
    ? `
    <div class="section-label">Connected Users · VIP View</div>
    <div class="admin-users-box" id="adminUsersList">
      <div class="admin-empty">Loading users...</div>
    </div>`
    : "";

  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Layz Hi-Res — BitChord Addon</title>
  <link rel="icon" type="image/svg+xml" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'%3E%3Cdefs%3E%3ClinearGradient id='g' x1='0' y1='0' x2='1' y2='1'%3E%3Cstop offset='0%25' stop-color='%2338bdf8'/%3E%3Cstop offset='100%25' stop-color='%23818cf8'/%3E%3C/linearGradient%3E%3C/defs%3E%3Crect width='64' height='64' rx='18' fill='url(%23g)'/%3E%3Cg fill='none' stroke='white' stroke-width='4.5' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='M26 44V20l22-4v24'/%3E%3Ccircle cx='20' cy='44' r='6'/%3E%3Ccircle cx='42' cy='40' r='6'/%3E%3C/g%3E%3C/svg%3E" />
  <link href="https://fonts.cdnfonts.com/css/sf-pro-display" rel="stylesheet" />
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    :root {
      --bg: #030612;
      --text: #f8fafc;
      --muted: rgba(226, 232, 240, 0.68);
      --glass-border: rgba(255, 255, 255, 0.2);
      --glass-highlight: rgba(255, 255, 255, 0.42);
      --accent: #38bdf8;
      --green: #4ade80;
      --yellow: #facc15;
      --red: #f87171;
      --font-sans: -apple-system, BlinkMacSystemFont, "SF Pro Display", "SF Pro Text", "Helvetica Neue", sans-serif;
      --font-mono: "SF Mono", ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    }

    body {
      font-family: var(--font-sans);
      -webkit-font-smoothing: antialiased;
      -moz-osx-font-smoothing: grayscale;
      background-color: var(--bg);
      color: var(--text);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 24px;
      position: relative;
    }

    .liquid-bg {
      position: fixed;
      inset: 0;
      z-index: -1;
      overflow: hidden;
      pointer-events: none;
    }
    .orb {
      position: absolute;
      border-radius: 50%;
      filter: blur(85px);
      opacity: 0.55;
      mix-blend-mode: screen;
      animation: floatOrb 18s ease-in-out infinite alternate;
    }
    .orb-1 {
      width: 440px; height: 440px; top: -110px; left: -90px;
      background: radial-gradient(circle, #0ea5e9 0%, #2563eb 55%, transparent 75%);
    }
    .orb-2 {
      width: 480px; height: 480px; bottom: -140px; right: -100px;
      background: radial-gradient(circle, #a855f7 0%, #6366f1 55%, transparent 75%);
      animation-duration: 22s; animation-delay: -5s;
    }
    .orb-3 {
      width: 340px; height: 340px; top: 42%; left: 55%;
      background: radial-gradient(circle, #2dd4bf 0%, #0284c7 55%, transparent 75%);
      opacity: 0.35; animation-duration: 26s; animation-delay: -10s;
    }
    @keyframes floatOrb {
      0% { transform: translate(0, 0) scale(1); }
      50% { transform: translate(45px, -35px) scale(1.12); }
      100% { transform: translate(-35px, 40px) scale(0.95); }
    }

    .card {
      position: relative;
      width: 100%;
      max-width: 548px;
      border-radius: 30px;
      padding: 36px 32px;
      background: linear-gradient(
        135deg,
        rgba(255, 255, 255, 0.13) 0%,
        rgba(255, 255, 255, 0.04) 48%,
        rgba(255, 255, 255, 0.09) 100%
      );
      backdrop-filter: blur(36px) saturate(185%);
      -webkit-backdrop-filter: blur(36px) saturate(185%);
      border: 1px solid var(--glass-border);
      box-shadow:
        0 30px 70px rgba(0, 0, 0, 0.55),
        inset 0 1.5px 1px var(--glass-highlight),
        inset 0 -1px 2px rgba(0, 0, 0, 0.35),
        inset 1px 0 1px rgba(255, 255, 255, 0.16);
      overflow-x: clip;
    }

    .card::before {
      content: "";
      position: absolute;
      inset: 0;
      border-radius: inherit;
      background: radial-gradient(
        420px circle at var(--mx, 50%) var(--my, 0%),
        rgba(255, 255, 255, 0.14),
        transparent 60%
      );
      pointer-events: none;
    }
    .card > * { position: relative; z-index: 1; }

    .top-bar {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 10px;
      margin-bottom: 24px;
      flex-wrap: wrap;
    }
    .status {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      font-size: 12px;
      font-weight: 600;
      color: #bbf7d0;
      background: linear-gradient(180deg, rgba(34, 197, 94, 0.22), rgba(34, 197, 94, 0.08));
      border: 1px solid rgba(134, 239, 172, 0.35);
      box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.3);
      padding: 6px 14px;
      border-radius: 999px;
      backdrop-filter: blur(12px);
    }
    .status.offline {
      color: #fecaca;
      background: linear-gradient(180deg, rgba(239, 68, 68, 0.24), rgba(239, 68, 68, 0.08));
      border-color: rgba(252, 165, 165, 0.35);
    }
    .dot {
      width: 8px; height: 8px; border-radius: 50%;
      background: var(--green); box-shadow: 0 0 12px var(--green);
      animation: pulse 2s infinite;
    }
    .status.offline .dot { background: var(--red); box-shadow: 0 0 12px var(--red); animation: none; }
    @keyframes pulse {
      0%, 100% { opacity: 1; transform: scale(1); }
      50% { opacity: 0.45; transform: scale(0.85); }
    }

    .pill-mono {
      font-family: var(--font-mono);
      font-size: 12px;
      color: rgba(248, 250, 252, 0.85);
      background: rgba(255, 255, 255, 0.08);
      padding: 6px 12px;
      border-radius: 999px;
      border: 1px solid rgba(255, 255, 255, 0.18);
      box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.28);
    }

    .brand { display: flex; align-items: center; gap: 16px; margin-bottom: 14px; }
    .logo {
      width: 54px; height: 54px; border-radius: 18px;
      background: linear-gradient(135deg, rgba(56, 189, 248, 0.85), rgba(129, 140, 248, 0.85));
      border: 1px solid rgba(255, 255, 255, 0.4);
      display: flex; align-items: center; justify-content: center;
      box-shadow: 0 12px 28px rgba(56, 189, 248, 0.35), inset 0 1.5px 1px rgba(255, 255, 255, 0.65);
      flex-shrink: 0;
    }
    h1 {
      font-size: 30px; font-weight: 700; letter-spacing: -0.025em;
      background: linear-gradient(180deg, #ffffff 10%, #bae6fd 100%);
      -webkit-background-clip: text; -webkit-text-fill-color: transparent;
    }
    .subtitle {
      font-size: 14.5px; color: var(--muted); line-height: 1.55;
      letter-spacing: -0.01em; margin-bottom: 24px;
    }
    .subtitle strong { color: #ffffff; font-weight: 600; }

    .metrics { display: grid; grid-template-columns: repeat(2, 1fr); gap: 12px; margin-bottom: 24px; }
    .metric {
      background: linear-gradient(160deg, rgba(255, 255, 255, 0.1), rgba(255, 255, 255, 0.03));
      border: 1px solid rgba(255, 255, 255, 0.15);
      box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.28);
      border-radius: 18px; padding: 13px 15px;
      transition: transform 0.2s ease, border-color 0.2s ease;
    }
    .metric:hover { transform: translateY(-2px); border-color: rgba(255, 255, 255, 0.3); }
    .metric-label {
      font-size: 10.5px; font-weight: 600; text-transform: uppercase;
      letter-spacing: 0.06em; color: var(--muted); margin-bottom: 6px;
    }
    .metric-value { font-family: var(--font-mono); font-size: 15px; font-weight: 600; color: var(--text); }

    .section-label {
      font-size: 11px; font-weight: 600; text-transform: uppercase;
      letter-spacing: 0.07em; color: var(--muted); margin-bottom: 10px;
    }

    .btn-discord {
      display: flex; align-items: center; justify-content: center; gap: 10px;
      width: 100%; padding: 14px 20px; border-radius: 18px;
      background: linear-gradient(180deg, rgba(88, 101, 242, 0.95), rgba(71, 82, 196, 0.95));
      border: 1px solid rgba(255, 255, 255, 0.32);
      box-shadow: 0 10px 24px rgba(88, 101, 242, 0.35), inset 0 1px 0 rgba(255, 255, 255, 0.45);
      color: #fff; text-decoration: none; font-size: 14.5px; font-weight: 600;
      margin-bottom: 24px; transition: transform 0.15s ease, box-shadow 0.15s ease;
      white-space: normal; text-align: center; line-height: 1.35;
    }
    .btn-discord svg { flex-shrink: 0; }
    .btn-discord:hover {
      transform: translateY(-1px);
      box-shadow: 0 12px 28px rgba(88, 101, 242, 0.5), inset 0 1px 0 rgba(255, 255, 255, 0.6);
    }

    .user-card {
      display: flex; align-items: center; justify-content: space-between; gap: 12px;
      background: rgba(255, 255, 255, 0.07);
      border: 1px solid rgba(255, 255, 255, 0.16);
      box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.25);
      border-radius: 18px; padding: 12px 14px; margin-bottom: 18px;
    }
    .user-info { display: flex; align-items: center; gap: 12px; min-width: 0; }
    .user-avatar {
      width: 38px; height: 38px; border-radius: 50%;
      border: 1.5px solid rgba(255, 255, 255, 0.35); flex-shrink: 0;
    }
    .user-name { font-size: 14px; font-weight: 600; color: #fff; margin-bottom: 3px; }
    .tier-pill {
      display: inline-block; font-size: 11px; font-weight: 600;
      padding: 2px 9px; border-radius: 999px; font-family: var(--font-mono);
    }
    .tier-pill.vip { background: rgba(56, 189, 248, 0.2); color: #7dd3fc; border: 1px solid rgba(125, 211, 252, 0.35); }
    .tier-pill.trial { background: rgba(250, 204, 21, 0.18); color: #fde047; border: 1px solid rgba(253, 224, 71, 0.35); }
    .tier-pill.expired { background: rgba(248, 113, 113, 0.2); color: #fca5a5; border: 1px solid rgba(252, 165, 165, 0.35); }
    .btn-logout {
      font-size: 12px; font-weight: 600; color: var(--muted); text-decoration: none;
      padding: 6px 12px; border-radius: 10px; background: rgba(255, 255, 255, 0.06);
      border: 1px solid rgba(255, 255, 255, 0.14); transition: background 0.15s ease, color 0.15s ease;
      flex-shrink: 0;
    }
    .btn-logout:hover { background: rgba(248, 113, 113, 0.2); color: #fecaca; }

    .expired-box {
      background: rgba(239, 68, 68, 0.14);
      border: 1px solid rgba(248, 113, 113, 0.35);
      border-radius: 16px; padding: 14px 16px; margin-bottom: 24px;
      font-size: 13px; color: #fecaca; line-height: 1.5;
    }

    .url-box {
      display: flex; align-items: center; gap: 8px;
      background: rgba(3, 6, 18, 0.42);
      border: 1px solid rgba(255, 255, 255, 0.16);
      box-shadow: inset 0 2px 6px rgba(0, 0, 0, 0.35), 0 1px 0 rgba(255, 255, 255, 0.12);
      border-radius: 18px; padding: 7px 7px 7px 16px; margin-bottom: 24px;
      min-width: 0;
    }
    .url-text {
      font-family: var(--font-mono); font-size: 12.5px; color: #f1f5f9;
      overflow: hidden; text-overflow: ellipsis; white-space: nowrap; flex: 1; min-width: 0;
    }
    .btn-copy {
      font-family: var(--font-sans);
      background: linear-gradient(180deg, rgba(56, 189, 248, 0.95), rgba(99, 102, 241, 0.95));
      color: #fff; border: 1px solid rgba(255, 255, 255, 0.35);
      box-shadow: 0 6px 18px rgba(56, 189, 248, 0.3), inset 0 1px 0 rgba(255, 255, 255, 0.55);
      border-radius: 12px; padding: 9px 17px; font-size: 13px; font-weight: 600;
      cursor: pointer; transition: transform 0.15s ease, box-shadow 0.15s ease; flex-shrink: 0;
    }
    .btn-copy:hover { transform: translateY(-1px); }
    .btn-copy.copied { background: linear-gradient(180deg, #22c55e, #16a34a); }

    .admin-users-box {
      background: linear-gradient(155deg, rgba(255, 255, 255, 0.07), rgba(255, 255, 255, 0.02));
      border: 1px solid rgba(255, 255, 255, 0.14);
      box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.2);
      border-radius: 16px;
      padding: 10px 14px;
      margin-bottom: 22px;
      display: flex;
      flex-direction: column;
      gap: 8px;
    }
    .admin-user-row {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 10px;
      font-size: 12.5px;
      padding: 4px 0;
      border-bottom: 1px solid rgba(255, 255, 255, 0.07);
    }
    .admin-user-row:last-child { border-bottom: none; }
    .admin-user-left {
      display: flex;
      align-items: center;
      gap: 8px;
      min-width: 0;
    }
    .status-dot {
      width: 7px; height: 7px; border-radius: 50%; flex-shrink: 0;
      background: rgba(148, 163, 184, 0.5);
    }
    .status-dot.active {
      background: var(--green);
      box-shadow: 0 0 8px var(--green);
    }
    .admin-user-name {
      font-weight: 600; color: #f8fafc;
      overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
    }
    .admin-user-right {
      display: flex; align-items: center; gap: 8px; flex-shrink: 0;
    }
    .admin-lastseen {
      font-family: var(--font-mono); font-size: 11px; color: var(--muted);
    }
    .btn-revoke {
      font-family: var(--font-sans);
      font-size: 11px;
      font-weight: 600;
      color: #fca5a5;
      background: rgba(239, 68, 68, 0.16);
      border: 1px solid rgba(248, 113, 113, 0.35);
      border-radius: 8px;
      padding: 3px 8px;
      cursor: pointer;
      transition: background 0.15s ease, color 0.15s ease;
    }
    .btn-revoke:hover {
      background: rgba(239, 68, 68, 0.32);
      color: #fff;
    }
    .admin-empty {
      font-size: 12px; color: var(--muted); text-align: center; padding: 6px 0;
    }

    .howto-box {
      background: linear-gradient(155deg, rgba(255, 255, 255, 0.07), rgba(255, 255, 255, 0.02));
      border: 1px solid rgba(255, 255, 255, 0.13);
      box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.2);
      border-radius: 14px;
      padding: 12px 15px;
      margin-bottom: 20px;
      font-size: 12.5px;
      color: #e2e8f0;
      line-height: 1.65;
      text-align: left;
      overflow-wrap: break-word;
      word-break: normal;
    }
    .howto-sep {
      color: var(--accent);
      margin: 0 5px;
      font-weight: 700;
    }

    .badges { display: grid; grid-template-columns: repeat(2, 1fr); gap: 10px; margin-bottom: 0; }
    .badge {
      background: linear-gradient(155deg, rgba(255, 255, 255, 0.09), rgba(255, 255, 255, 0.02));
      border: 1px solid rgba(255, 255, 255, 0.14);
      box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.24);
      border-radius: 16px; padding: 13px 15px;
      transition: transform 0.2s ease, background 0.2s ease, border-color 0.2s ease;
    }
    .badge:hover {
      transform: translateY(-2px);
      background: linear-gradient(155deg, rgba(255, 255, 255, 0.14), rgba(255, 255, 255, 0.04));
      border-color: rgba(255, 255, 255, 0.28);
    }
    .badge-title { font-size: 13.5px; font-weight: 600; color: #ffffff; margin-bottom: 3px; }
    .badge-sub { font-size: 11.5px; color: var(--muted); }

    @media (max-width: 480px) {
      body { padding: 14px; }
      .card { padding: 20px 16px; border-radius: 22px; }
      .top-bar { margin-bottom: 16px; }
      .brand { gap: 12px; margin-bottom: 10px; }
      .logo { width: 44px; height: 44px; border-radius: 14px; }
      h1 { font-size: 24px; }
      .subtitle { font-size: 13px; margin-bottom: 16px; }
      .metrics { gap: 8px; margin-bottom: 16px; }
      .metric { padding: 10px 12px; border-radius: 14px; }
      .btn-discord { padding: 12px 14px; margin-bottom: 16px; font-size: 13.5px; }
      .user-card { padding: 10px 12px; margin-bottom: 14px; }
      .url-box { margin-bottom: 16px; }
      .howto-box { padding: 10px 12px; margin-bottom: 16px; font-size: 11.5px; }
      .badges { gap: 8px; }
      .badge { padding: 10px 12px; border-radius: 14px; }
      .badge-title { font-size: 12.5px; }
    }
  </style>
</head>
<body>
  <div class="liquid-bg">
    <div class="orb orb-1"></div>
    <div class="orb orb-2"></div>
    <div class="orb orb-3"></div>
  </div>

  <main class="card" id="glassCard">
    <div class="top-bar">
      <div class="status" id="statusPill">
        <span class="dot"></span>
        <span id="statusText">Checking...</span>
      </div>
      <span class="pill-mono">v1.1.0</span>
    </div>

    <div class="brand">
      <div class="logo">
        <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M9 18V5l12-2v13"></path>
          <circle cx="6" cy="18" r="3"></circle>
          <circle cx="18" cy="16" r="3"></circle>
        </svg>
      </div>
      <div>
        <h1>Layz Hi-Res</h1>
      </div>
    </div>

    <p class="subtitle">
      Custom audio streaming addon for <strong>BitChord</strong>. Automatically supports Hi-Res 24-bit FLAC, 16-bit Lossless, and Dolby Atmos streaming.
    </p>

    <div class="metrics">
      <div class="metric">
        <div class="metric-label">Uptime</div>
        <div class="metric-value" id="metricUptime">--</div>
      </div>
      <div class="metric">
        <div class="metric-label">Users</div>
        <div class="metric-value" id="metricUsers">--</div>
      </div>
    </div>

    ${accessSectionHtml}
    ${adminUsersSectionHtml}

    <div class="section-label">How to Add</div>
    <div class="howto-box">
      Open BitChord<span class="howto-sep">›</span><wbr>Profiles<span class="howto-sep">›</span><wbr>Settings<span class="howto-sep">›</span><wbr>Sources<span class="howto-sep">›</span><wbr>Add an addon<span class="howto-sep">›</span><wbr>Paste URL
    </div>

    <div class="section-label">Supported Audio Tiers</div>
    <div class="badges">
      <div class="badge">
        <div class="badge-title">Hi-Res Lossless</div>
        <div class="badge-sub">FLAC · 24-bit / up to 192 kHz</div>
      </div>
      <div class="badge">
        <div class="badge-title">Lossless</div>
        <div class="badge-sub">FLAC · 16-bit / 44.1 kHz</div>
      </div>
      <div class="badge">
        <div class="badge-title">Dolby Atmos</div>
        <div class="badge-sub">E-AC-3 JOC · Spatial Audio</div>
      </div>
      <div class="badge">
        <div class="badge-title">High &amp; Low</div>
        <div class="badge-sub">AAC · 320 kbps &amp; 128 kbps</div>
      </div>
    </div>
  </main>

  <script>
    var card = document.getElementById("glassCard");
    card.addEventListener("mousemove", function(e) {
      var rect = card.getBoundingClientRect();
      card.style.setProperty("--mx", (e.clientX - rect.left) + "px");
      card.style.setProperty("--my", (e.clientY - rect.top) + "px");
    });

    function formatUptime(sec) {
      var d = Math.floor(sec / 86400);
      var h = Math.floor((sec % 86400) / 3600);
      var m = Math.floor((sec % 3600) / 60);
      var s = sec % 60;
      if (d > 0) return d + "d " + h + "h";
      if (h > 0) return h + "h " + m + "m";
      if (m > 0) return m + "m " + s + "s";
      return s + "s";
    }

    function formatAgo(ms) {
      var sec = Math.max(0, Math.floor((Date.now() - ms) / 1000));
      if (sec < 60) return sec + "s ago";
      var min = Math.floor(sec / 60);
      if (min < 60) return min + "m ago";
      return Math.floor(min / 60) + "h ago";
    }

    function escapeText(str) {
      return String(str)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;");
    }

    function updateTrialCountdown() {
      var el = document.getElementById("trialCountdown");
      if (!el) return;
      var exp = Number(el.getAttribute("data-exp"));
      var diff = Math.max(0, Math.floor((exp - Date.now()) / 1000));
      if (diff <= 0) {
        el.textContent = "Trial Expired";
        el.className = "tier-pill expired";
        return;
      }
      var h = Math.floor(diff / 3600);
      var m = Math.floor((diff % 3600) / 60);
      var s = diff % 60;
      el.textContent = "Trial · " + h + "h " + m + "m " + s + "s";
    }
    updateTrialCountdown();
    setInterval(updateTrialCountdown, 1000);

    async function revokeUser(btn) {
      var uid = btn.getAttribute("data-uid");
      var name = btn.getAttribute("data-name") || uid;
      if (!confirm("Revoke access for " + name + "?")) return;
      btn.disabled = true;
      btn.textContent = "...";
      try {
        var resp = await fetch("/admin/revoke/" + encodeURIComponent(uid), { method: "POST" });
        if (resp.ok) {
          loadAdminUsers();
          checkPing();
        }
      } catch (err) {
        btn.disabled = false;
        btn.textContent = "Revoke";
      }
    }

    async function loadAdminUsers() {
      var box = document.getElementById("adminUsersList");
      if (!box) return;
      try {
        var resp = await fetch("/admin/users", { cache: "no-store" });
        if (!resp.ok) return;
        var data = await resp.json();
        if (!data.users || data.users.length === 0) {
          box.innerHTML = '<div class="admin-empty">No active users yet</div>';
          return;
        }
        box.innerHTML = data.users.map(function(u) {
          var pillClass = u.role === "VIP" ? "vip" : "trial";
          var dotClass = u.isActive ? "status-dot active" : "status-dot";
          var revokeBtn = (u.role !== "VIP" && u.uid)
            ? '<button class="btn-revoke" data-uid="' + escapeText(u.uid) + '" data-name="' + escapeText(u.username) + '" onclick="revokeUser(this)">Revoke</button>'
            : '';
          return (
            '<div class="admin-user-row">' +
              '<div class="admin-user-left">' +
                '<span class="' + dotClass + '"></span>' +
                '<span class="admin-user-name">' + escapeText(u.username) + '</span>' +
              '</div>' +
              '<div class="admin-user-right">' +
                '<span class="tier-pill ' + pillClass + '">' + u.role + '</span>' +
                '<span class="admin-lastseen">' + formatAgo(u.lastSeen) + '</span>' +
                revokeBtn +
              '</div>' +
            '</div>'
          );
        }).join("");
      } catch (err) {}
    }

    async function checkPing() {
      var pill = document.getElementById("statusPill");
      var statusText = document.getElementById("statusText");
      var metricUptime = document.getElementById("metricUptime");
      var metricUsers = document.getElementById("metricUsers");

      var start = performance.now();
      try {
        var resp = await fetch("/ping", { cache: "no-store" });
        var latency = Math.round(performance.now() - start);
        if (!resp.ok) throw new Error("HTTP " + resp.status);
        var data = await resp.json();

        pill.classList.remove("offline");
        statusText.textContent = "Server Online · " + latency + " ms";
        metricUptime.textContent = formatUptime(data.uptime || 0);
        metricUsers.textContent = (data.activeUsers || 0) + " active";
      } catch (err) {
        pill.classList.add("offline");
        statusText.textContent = "Server Offline";
      }
    }

    checkPing();
    loadAdminUsers();
    setInterval(function() {
      checkPing();
      loadAdminUsers();
    }, 5000);

    function copyManifest() {
      var text = document.getElementById("manifestUrl").innerText;
      var btn = document.getElementById("copyBtn");
      navigator.clipboard.writeText(text).then(function() {
        btn.innerText = "Copied!";
        btn.classList.add("copied");
        setTimeout(function() {
          btn.innerText = "Copy URL";
          btn.classList.remove("copied");
        }, 2000);
      });
    }
  </script>
</body>
</html>`);
}
