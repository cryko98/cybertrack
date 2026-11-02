# $CYBERTRACKER

Landing page for the $CYBERTRACKER Solana memecoin: a live cyber attack tracker built around a holographic 3D globe.

Static site: no build step and no backend. All data is fetched in the visitor's browser from public threat-intel feeds.

## Live data

| Panel | Source |
| --- | --- |
| Threat level, attack reports (24h), unique attacking IPs, top ports, attacking IPs | [SANS Internet Storm Center / DShield](https://isc.sans.edu/api/) |
| Ransomware victims (7d), top gangs, most hit countries | [ransomware.live](https://www.ransomware.live) (newest ~320 KB streamed only) |
| Crypto Attack Radar: stolen totals, latest hacks, chains, attack vectors | [DeFiLlama hacks](https://defillama.com/hacks) |
| SOL drainer / phishing domains | [ScamSniffer](https://github.com/scamsniffer/scam-database) |
| Exploited CVE ticker and count | [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) via `cisagov/kev-data` |
| IPs on 5+ blocklists | [stamparm/ipsum](https://github.com/stamparm/ipsum) |
| Attacker geolocation | [ipapi.is](https://ipapi.is), with a fallback to the ISC AS country |

The globe replays these real events continuously:

- Red arcs run from attacking IPs to the DShield sensor grid.
- Amber pulses mark ransomware victim countries. Purple pulses mark crypto-sector victims.
- Crypto hacks raise an alert banner and light up the chain nodes floating above the globe. DPRK-attributed thefts get an arc from Pyongyang.

Interactive features:

- Click a country, an attacker, a chain node, a feed item or a hack for an intel panel.
- Toggle layers on and off.
- Pause the rotation, zoom, or reset the view.

## Configure

Edit the top of `js/app.js`:

```js
const CONFIG = {
  CA: "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", // contract address
  X_URL: "#",                            // X / Twitter link
};
```

## Run locally

```bash
npx http-server . -p 5173
```

Deploys as-is to Vercel, Netlify, GitHub Pages or any static host.
