import crypto from "crypto";
import fetch from "node-fetch";

// Helper functions
function b64url(buffer) {
  return buffer.toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}
function sha256(input) {
  return crypto.createHash("sha256").update(input).digest();
}

// Temporary in-memory store (for demo only; use DB in production)
let sessions = {};

export default async function handler(req, res) {
  const { query } = req;

  // Step 1: /auth
  if (req.url.startsWith("/api/canva/auth")) {
    const code_verifier = b64url(crypto.randomBytes(64));
    const code_challenge = b64url(sha256(code_verifier));
    const state = b64url(crypto.randomBytes(16));

    sessions[state] = { code_verifier };

    const params = new URLSearchParams({
      response_type: "code",
      client_id: process.env.CANVA_CLIENT_ID,
      redirect_uri: process.env.REDIRECT_URI,
      scope: process.env.SCOPES,
      state,
      code_challenge,
      code_challenge_method: "S256",
    });

    res.writeHead(302, {
      Location: `${process.env.CANVA_AUTH_ENDPOINT}?${params}`,
    });
    res.end();
    return;
  }

  // Step 2: /callback
  if (req.url.startsWith("/api/canva/callback")) {
    const { code, state } = query;

    if (!state || !sessions[state]) {
      res.status(400).send("Invalid state");
      return;
    }

    const code_verifier = sessions[state].code_verifier;

    const body = new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: process.env.REDIRECT_URI,
      client_id: process.env.CANVA_CLIENT_ID,
      code_verifier,
    });

    const r = await fetch(process.env.CANVA_TOKEN_ENDPOINT, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body,
    });
    const data = await r.json();

    if (!r.ok || !data.access_token) {
      res.status(500).send(`Token exchange failed: ${JSON.stringify(data)}`);
      return;
    }

    res.status(200).send("✅ Connected to Canva! You can close this window.");
    return;
  }

  res.status(404).send("Not found");
}
