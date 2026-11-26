# Layz Hi-Res

A custom audio streaming addon for **BitChord** with automatic Hi-Res 24-bit FLAC, 16-bit Lossless, and Dolby Atmos support, featuring a dark-glass web dashboard and Discord OAuth2 access control.

## Features

- **Multi-Tier Audio Quality**
  - **Hi-Res Lossless:** FLAC · 24-bit / up to 192 kHz (DASH & direct)
  - **Lossless:** FLAC · 16-bit / 44.1 kHz
  - **Dolby Atmos:** E-AC-3 JOC · Spatial Audio
  - **High & Low:** AAC · 320 kbps & 128 kbps
- **Discord OAuth2 Access Control:** Generates a unique, signed personal manifest URL (`/u/<token>/manifest.json`) per user.
- **Trial & VIP System:** Configurable trial duration (default: 24 hours) for standard users and permanent access for whitelisted VIP Discord IDs.
- **Live Dashboard:** Real-time server status, latency, uptime, active user count, and live trial countdown.
- **BitChord Manifest Status:** Displays the user's Discord username and VIP/Trial status directly inside BitChord's addon list.

## How to Use

1. Open the dashboard at **`https://layyyz.web.id`**.
2. Click **Login with Discord to Generate URL** and authorize your account.
3. Click **Copy URL** to copy your **Personal Manifest URL**.
4. In **BitChord**, go to:
   **Profiles → Settings → Sources → Add an addon → Paste URL**.

## Local Development

```bash
npm install
npm start
```
