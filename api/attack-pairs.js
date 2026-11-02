// Vercel serverless function: real attack origin → target country pairs from Cloudflare Radar.
// Needs the CLOUDFLARE_API_TOKEN environment variable (custom token with Account › Radar › Read).
// Cloudflare updates this data about hourly, so the edge cache keeps a response for 1 hour.
// The cache only refreshes when a visitor requests it, so without traffic Cloudflare is never called.

const BASE = "https://api.cloudflare.com/client/v4/radar/attacks";

async function radar(path, token) {
  const r = await fetch(`${BASE}${path}`, { headers: { Authorization: `Bearer ${token}` } });
  if (!r.ok) throw new Error(`Cloudflare Radar ${r.status}`);
  const j = await r.json();
  return j.result;
}

const toPairs = (result, layer) => (result?.top_0 || []).map(p => ({
  layer,
  from: p.originCountryAlpha2,
  fromName: p.originCountryName,
  to: p.targetCountryAlpha2,
  toName: p.targetCountryName,
  share: Number(p.value),
}));

module.exports = async (req, res) => {
  const token = process.env.CLOUDFLARE_API_TOKEN;
  if (!token) {
    res.status(503).json({ error: "CLOUDFLARE_API_TOKEN is not configured" });
    return;
  }
  try {
    const query = "?dateRange=1d&limit=40&limitDirection=ORIGIN&limitPerLocation=4&format=JSON";
    const [l7, l3] = await Promise.allSettled([
      radar(`/layer7/top/attacks${query}`, token),
      radar(`/layer3/top/attacks${query}`, token),
    ]);
    const pairs = [
      ...(l7.status === "fulfilled" ? toPairs(l7.value, "L7") : []),
      ...(l3.status === "fulfilled" ? toPairs(l3.value, "L3") : []),
    ].filter(p => p.from && p.to && p.from !== p.to);
    if (!pairs.length) throw new Error("No data from Cloudflare Radar");

    const meta = (l7.status === "fulfilled" ? l7.value : l3.value)?.meta || {};
    // Fresh for 1h; after that the next visitor gets the cached copy instantly while it refreshes in the background
    res.setHeader("Cache-Control", "s-maxage=3600, stale-while-revalidate=86400");
    res.status(200).json({
      source: "Cloudflare Radar",
      window: meta.dateRange?.[0] || null,
      lastUpdated: meta.lastUpdated || null,
      pairs,
    });
  } catch (e) {
    res.status(502).json({ error: String(e.message || e) });
  }
};
