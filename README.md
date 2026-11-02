# $CYBERTRACKER

Landing page for the $CYBERTRACKER Solana memecoin: a live cyber attack tracker built around a holographic 3D globe.

Static site: no build step and no backend. All data is fetched in the visitor's browser from public threat-intel feeds.

## Live data

| Panel | Source |
| --- | --- |
| Threat level, attack reports (24h), unique attacking IPs, top ports, attacking IPs | [SANS Internet Storm Center / DShield](https://isc.sans.edu/api/) |
| Ransomware victims (7d), top gangs, most hit countries | [ransomware.live](https://www.ransomware.live) (newest ~320 KB streamed only) |
| Exploited CVE ticker and count | [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) via `cisagov/kev-data` |
| IPs on 5+ blocklists | [stamparm/ipsum](https://github.com/stamparm/ipsum) |
| Attacker geolocation | [ipapi.is](https://ipapi.is), with a fallback to the ISC AS country |

The globe replays these real events continuously. Red arcs run from attacking IPs to the DShield sensor grid, and amber pulses mark ransomware victim countries.

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
