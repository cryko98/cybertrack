# $CYBERTRACKER

Landing page for the $CYBERTRACKER Solana memecoin: a cyber attack tracker built around a holographic 3D globe.

The site is static and has no build step. Almost all data is fetched in the visitor's browser from public threat-intel feeds. The one exception is a single Vercel function, which proxies Cloudflare Radar so the API token stays secret.

## Data sources

| Panel | Source |
| --- | --- |
| Attack route arcs: origin → target country, last 24h | [Cloudflare Radar](https://radar.cloudflare.com/security) via `api/attack-pairs.js` |
| Threat level, daily attack reports, unique attacking IPs, top ports, top attacking IPs | [SANS Internet Storm Center / DShield](https://isc.sans.edu/api/) |
| Ransomware victims (7d), top gangs, most hit countries | [ransomware.live](https://www.ransomware.live) (only the newest ~320 KB is streamed) |
| Crypto Attack Radar: stolen totals, latest hacks, chains, attack vectors | [DeFiLlama hacks](https://defillama.com/hacks) |
| SOL drainer / phishing domains | [ScamSniffer](https://github.com/scamsniffer/scam-database) |
| Exploited CVE ticker and count | [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) via `cisagov/kev-data` |
| IPs on 5+ blocklists | [stamparm/ipsum](https://github.com/stamparm/ipsum) |
| Attacker geolocation (approximate) | [ipapi.is](https://ipapi.is), with a fallback to the ISC AS country |

## How the map works

Nothing on the map is simulated.

- Red arcs are real Cloudflare Radar origin → target country pairs. Without a token, no arcs are drawn.
- Red dots are top attacking IPs from SANS ISC, placed by IP geolocation.
- Amber pulses are ransomware victims at their country. Purple pulses are crypto-sector victims.
- Chain badges rank blockchains by 12-month hack losses. Their position on the globe is symbolic.
- The feed cycles through the latest real events, and every entry shows its own age. Crypto alerts only fire for hacks from the last 7 days.
- The ⓘ Data button on the globe explains all of this to visitors.

## Configure

The contract address and X link are at the top of `js/app.js`. Until `CA` is a valid Solana address, the header shows "Coming soon".

```js
const CONFIG = {
  CA: "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", // contract address
  X_URL: "#",                            // X / Twitter link
};
```

### Cloudflare Radar (attack routes)

1. In the Cloudflare dashboard, open My Profile › API Tokens › Create Token › Custom token, and give it the **Account › Radar › Read** permission.
2. In Vercel, open the project's Settings › Environment Variables, add `CLOUDFLARE_API_TOKEN`, then redeploy.

## Run locally

```bash
npx http-server . -p 5173
```

Locally the `/api` function does not run, so the attack route arcs stay off. Use `vercel dev` to test them.
