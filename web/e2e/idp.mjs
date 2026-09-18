// A minimal OpenID provider for the browser tests. It signs real RS256 ID
// tokens and enforces the PKCE challenge, so the service's relying party runs
// its genuine code path rather than a stub. Test scaffolding only.
import { createServer } from "node:http";
import { createHash, generateKeyPairSync, randomUUID, sign } from "node:crypto";

const port = Number(process.env.IDP_PORT ?? 18091);
const issuer = `http://127.0.0.1:${port}`;
const clientId = "securesend";
// A fixture, not a credential: the test service is configured with the same.
const clientSecret = process.env.IDP_CLIENT_SECRET ?? "dev";

const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
// generateKeyPairSync already hands back key objects, so they are used as is.
const jwk = publicKey.export({ format: "jwk" });
const key = privateKey;
const codes = new Map();

// Which user the next sign-in produces. A test changes it by asking for
// /switch?email=..., because the provider has no login screen of its own.
let currentUser = { email: "alice@acme.com", emailVerified: true };

const b64url = (input) => Buffer.from(input).toString("base64url");

function makeIdToken(nonce) {
  const now = Math.floor(Date.now() / 1000);
  const claims = {
    iss: issuer,
    sub: `sub-${currentUser.email}`,
    aud: clientId,
    exp: now + 300,
    iat: now,
    nonce,
    email: currentUser.email,
    preferred_username: currentUser.email,
  };
  if (currentUser.emailVerified !== undefined) claims.email_verified = currentUser.emailVerified;
  const signingInput = `${b64url(JSON.stringify({ alg: "RS256", typ: "JWT", kid: "test-1" }))}.${b64url(JSON.stringify(claims))}`;
  const signature = sign("RSA-SHA256", Buffer.from(signingInput), key).toString("base64url");
  return `${signingInput}.${signature}`;
}

function json(res, body, status = 200) {
  const payload = JSON.stringify(body);
  res.writeHead(status, { "content-type": "application/json", "content-length": Buffer.byteLength(payload) });
  res.end(payload);
}

const server = createServer(async (req, res) => {
  const url = new URL(req.url, issuer);

  if (url.pathname === "/.well-known/openid-configuration") {
    return json(res, {
      issuer,
      authorization_endpoint: `${issuer}/authorize`,
      token_endpoint: `${issuer}/token`,
      jwks_uri: `${issuer}/jwks`,
      response_types_supported: ["code"],
      subject_types_supported: ["public"],
      id_token_signing_alg_values_supported: ["RS256"],
      scopes_supported: ["openid", "profile", "email"],
      token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post"],
      code_challenge_methods_supported: ["S256"],
      claims_supported: ["sub", "email", "email_verified", "preferred_username"],
    });
  }

  if (url.pathname === "/jwks") {
    return json(res, { keys: [{ kty: "RSA", use: "sig", alg: "RS256", kid: "test-1", n: jwk.n, e: jwk.e }] });
  }

  if (url.pathname === "/switch") {
    currentUser = {
      email: url.searchParams.get("email") ?? "alice@acme.com",
      emailVerified: url.searchParams.get("verified") === "false" ? false : true,
    };
    return json(res, { ok: true, user: currentUser });
  }

  if (url.pathname === "/authorize") {
    const code = randomUUID();
    codes.set(code, {
      nonce: url.searchParams.get("nonce"),
      challenge: url.searchParams.get("code_challenge"),
    });
    const back = new URL(url.searchParams.get("redirect_uri"));
    back.searchParams.set("code", code);
    back.searchParams.set("state", url.searchParams.get("state"));
    res.writeHead(303, { location: back.toString() });
    return res.end();
  }

  if (url.pathname === "/token" && req.method === "POST") {
    const body = await new Promise((resolve) => {
      let raw = "";
      req.on("data", (chunk) => (raw += chunk));
      req.on("end", () => resolve(new URLSearchParams(raw)));
    });
    const header = req.headers.authorization ?? "";
    const basic = header.startsWith("Basic ")
      ? Buffer.from(header.slice(6), "base64").toString() === `${clientId}:${clientSecret}`
      : false;
    const post = body.get("client_id") === clientId && body.get("client_secret") === clientSecret;
    if (!basic && !post) return json(res, { error: "invalid_client" }, 401);

    const pending = codes.get(body.get("code"));
    codes.delete(body.get("code"));
    if (!pending) return json(res, { error: "invalid_grant" }, 400);
    const expected = createHash("sha256").update(body.get("code_verifier")).digest("base64url");
    if (expected !== pending.challenge) return json(res, { error: "invalid_grant", error_description: "pkce" }, 400);

    return json(res, {
      access_token: "dev",
      token_type: "Bearer",
      expires_in: 300,
      id_token: makeIdToken(pending.nonce),
    });
  }

  res.writeHead(404).end();
});

server.listen(port, "127.0.0.1", () => console.log(`test identity provider on ${issuer}`));
