import crypto from "crypto";

// Helpers
const b64url = (buf) =>
  buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const sha256 = (input) => crypto.createHash("sha256").update(input).digest();

const setCookie = (res, name, value, maxAgeSec = 600) => {
  const cookie = `${name}=${encodeURIComponent(value)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAgeSec}`;
  res.setHeader("Set-Cookie", [...(res.getHeader("Set-Cookie") || []), cookie]);
};

const getCookies = (req) => {
  const header = req.headers.cookie || "";
  return header.split(";").reduce((acc, part) => {
    const i = part.indexOf("=");
    if (i > -1) {
      const k = part.slice(0, i).trim();
      const v = decodeURIComponent(part.slice(i + 1).trim());
      acc[k] = v;
    }
    return acc;
  }, {});
};

export default async function handler(req, res) {
  // Route: /api/canva/auth
  if (req.url.startsWith("/api/canva/auth")) {
    const code_verifier = b64url(crypto.randomBytes(64));
    const code_challenge = b64url(sha256(code_verifier));
    const state = b64url(crypto.randomBytes(16));

    // Store verifier + state in secure cookies
    setCookie(res, "cv", code_verifier);
    setCookie(res, "st", state);

    const params = new URLSearchParams({
      response_type: "code",
      client_id: process.env.CANVA_CLIENT_ID,
      redirect_uri: process.env.REDIRECT_URI,
      scope: process.env.SCOPES,
      state,
      code_challenge,
      code_challenge_method: "S256",
    });

    res.writeHead(302, { Location: `${process.env.CANVA_AUTH_ENDPOINT}?${params}` });
    res.end();
    return;
  }

  // Route: /api/canva/callback
  if (req.url.startsWith("/api/canva/callback")) {
    const url = new URL(req.url, `https://${req.headers.host}`);
    const code = url.searchParams.get("code");
    const state = url.searchParams.get("state");
    const cookies = getCookies(req);

    const stateCookie = cookies["st"];
    const codeVerifier = cookies["cv"];

    if (!code || !state || !stateCookie || !codeVerifier || state !== stateCookie) {
      res.statusCode = 400;
      res.end("Invalid state or

