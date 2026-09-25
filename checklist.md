# SSO Penetration Testing Checklist (with Burp Suite Testing Methods)
### SAML · OAuth 2.0 · OpenID Connect

---

## STAGE 1 — RECON

### 1.1 Endpoint & Metadata Discovery

| # | Test Case | Method | Burp Testing Steps | Pass | Fail |
|---|-----------|--------|--------------------|------|------|
| 1.1.1 | Enumerate SSO endpoints | Crawl, JS analysis, mobile traffic | Crawl with **Burp Spider**; use **Engagement tools → Discover content** on `/saml`, `/oauth`, `/.well-known`; check **Site map** for ACS/authorize/token/userinfo; grep History for `SAMLResponse`, `code=`, `id_token=` | All endpoints documented | Unlisted endpoints accept traffic |
| 1.1.2 | SAML metadata inspection | Fetch `metadata.xml` | Send request to **Repeater** → **Send to Comparer** against known-good metadata; inspect certs in response; save X.509 for SAML Raider keystore | Entity IDs/certs match prod; strong sig alg | SHA-1, stale endpoints |
| 1.1.3 | OIDC discovery review | Fetch `openid-configuration` | Repeater; note `jwks_uri`, copy to **SAML Raider / JWT Editor** for key loading; save response to site map | Config consistent, no implicit flows | `token` response type exposed |
| 1.1.4 | Fingerprint implementation | Banner/error analysis | Add **Logger++**; inspect cookies (`SimpleSAMLAuthToken`, `KEYCLOAK_IDENTITY`, `PF`, `JSESSIONID`), error page bodies; match against known stacks/CVEs | Stack identified | Unpatched version |

### 1.2 Certificate & Cryptographic Hygiene

| # | Test Case | Method | Burp Testing Steps | Pass | Fail |
|---|-----------|--------|--------------------|------|------|
| 1.2.1 | Signing algorithm audit | Decode tokens | Intercept login; send token to **Decoder** → Base64 → inspect `alg`/`SigMethod`; or **JWT Editor** shows header automatically | RSA-SHA256+/ECDSA/EdDSA only | SHA-1, DSA, `alg:none` |
| 1.2.2 | Key management | JWKS review | Request `jwks_uri` in Repeater; check `kid`s, key sizes; use **JWT Editor → New Key → Load from JWKs**; search History for embedded keys in JS via **Search** (`kty`, `BEGIN RSA`) | ≥2048-bit, rotation enforced | Static JWKS, keys in JS bundle |

### 1.3 Trust Mapping

| # | Test Case | Method | Burp Testing Steps | Pass | Fail |
|---|-----------|--------|--------------------|------|------|
| 1.3.1 | SP/IdP trust matrix | Doc all RPs | Review full login flow in HTTP History (logger++); map `client_id`s, `aud` values, ACS URLs across all apps in scope | Trust minimal/explicit | Wildcard trust |
| 1.3.2 | Token exchange surface | Identify grants | For each `client_id`, test `grant_type=` values in **Repeater** (`authorization_code`, `refresh_token`, `password`, `client_credentials`, `urn:ietf:params:oauth:grant-type:token-exchange`) | Only required grants | Legacy grants enabled |

---

## STAGE 2 — ASSERTION / TOKEN ANALYSIS

### 2.1 XML Signature Wrapping (XSW 1–8) — Burp with SAML Raider

> **Setup:** Install **SAML Raider** (BApp Store). Capture full auth flow via proxy. In HTTP History, find POST to ACS containing `SAMLResponse` → right-click → **Extensions → SAML Raider → Send to SAML Raider**. SAML Raider auto-decodes Base64+Deflate.

| # | Variant | Technique | Burp Testing Steps | Pass | Fail |
|---|---------|-----------|--------------------|------|------|
| XSW-1 | New Response wrapper | Original signed Assertion moved into new Response; second modified unsigned Assertion added | SAML Raider → **XSW 1** button (auto-generates wrapped message) → Observe difference between validation vs. application attribute values → Forward, watch response | Modified assertion rejected | Session with attacker attributes |
| XSW-2 | Response-in-Response | Original signed Response embedded in new malicious Response | SAML Raider → **XSW 2** → Forward to ACS | Nested Response rejected | Tampered inner content processed |
| XSW-3 | Duplicate Assertion | Duplicate Assertion (2nd unsigned, modified) in same Response | SAML Raider → **XSW 3** → Forward | Duplicate rejected | Second assertion processed |
| XSW-4 | Response wrap + mod assertion | Original Response inside new Response; modify inner assertion | SAML Raider → **XSW 4** → edit inner assertion in message editor → Forward | Signature covers processed node | Outer/tampered assertion honored |
| XSW-5 | Duplicate Response | Sibling duplicate Response elements | SAML Raider → **XSW 5** → Forward | Envelope validation rejects | Unsigned duplicate processed |
| XSW-6 | Signature → Object | Signature moved into `<Object>` child of Signature | SAML Raider → **XSW 6** → verify which node signature references → Forward | Reference validation fails | Sibling content modification accepted |
| XSW-7 | Content after Signature | Signed content kept; modified unsigned content placed after `<Signature>` | SAML Raider → **XSW 7** → Forward | Only signed content used | Post-signature content processed |
| XSW-8 | Namespace confusion | Namespace alias tricks so validator/logic resolve different nodes | Manual: send to **Repeater**; edit XML directly — inject `xmlns:ns1`, rename wrapper to `ns1:Response`, keep signed inner with original prefix; ensure C14N discrepancy → Forward | Consistent C14N, same node | Different nodes for sig vs. logic |

**XSW verification in Burp:** After forwarding, check response for session cookie/redirect; then **Repeater** the same attack to confirm reproducibility; use **Comparer** on valid vs. attack response to confirm session issuance.

### 2.2 SAML Assertion Manipulation

| # | Test Case | Method | Burp Testing Steps | Pass | Fail |
|---|-----------|--------|--------------------|------|------|
| 2.2.1 | Signature removal | Strip `<Signature>` | SAML Raider → **Remove Signatures** → Forward; also manual delete in Repeater | Rejected | Accepted unsigned |
| 2.2.2 | AudienceRestriction bypass | Change `<Audience>` to other SP / delete element | SAML Raider → edit XML → Forward; test cross-SP with assertion from second SP in Repeater | Rejected on audience mismatch | Token substitution works |
| 2.2.3 | InResponseTo validation | Replay assertion with missing/mismatched InResponseTo | Repeater: capture valid response → remove `InResponseTo` attr → send; also replay same response twice | Bound to request ID, single-use | Replay/cross-request accepted |
| 2.2.4 | Conditions tampering | Edit NotBefore/NotOnOrAfter | SAML Raider → edit → set `NotOnOrAfter` to past / `NotBefore` to future → Forward | Time window enforced | Expired/future assertion accepted |
| 2.2.5 | Recipient/Destination tamper | Modify Recipient, Destination, ACSURL | SAML Raider → edit attributes → Forward; test sending to different ACS path in Repeater | Exact match required | Alternate endpoint honored |
| 2.2.6 | SubjectConfirmationData tamper | Remove Recipient/InResponseTo/Address | SAML Raider → edit → Forward | All fields validated | Bearer assertion context-free |
| 2.2.7 | Attribute injection | Add Role/Groups/email; duplicate NameID | SAML Raider → **Re-sign** modified assertion if needed, or inject attribute in unsigned copy (pair with XSW) | Whitelist enforced | Privilege escalation |
| 2.2.8 | Assertion replay | Re-send same signed assertion | Repeater → send same POST twice (within validity) → check both create sessions; repeat after logout | Single-use/replay cache | Multiple sessions |
| 2.2.9 | XXE/DTD injection | Insert DOCTYPE/entities/comments | Repeater → inject `<!DOCTYPE...>` with file/SSRF entity (point to **Burp Collaborator**) into assertion → Forward | DTD rejected, no callbacks | Collaborator ping = XXE |

### 2.3 OAuth/OIDC Token-Level Flaws (Burp + JWT Editor)

> **Setup:** Install **JWT Editor** extension. Intercept token-bearing request → right-click → **Extensions → JWT Editor → Send to JWT Editor** (or edit in Repeater with JWT Editor tab).

| # | Test Case | Method | Burp Testing Steps | Pass | Fail |
|---|-----------|--------|--------------------|------|------|
| 2.3.1 | RS256→HS256 confusion | Sign with public key as HMAC secret | JWT Editor → change `alg` to HS256 → **JWT Editor → Load Key** (paste SP public key from JWKS in PEM) → sign → Forward | Rejected (alg allowlist) | Token accepted → impersonation |
| 2.3.2 | alg:none | Empty signature | JWT Editor → set `"alg":"none"` → check "None" algorithm option → Forward | Rejected | Unsigned accepted |
| 2.3.3 | jku/x5u injection | Attacker JWKS in header | JWT Editor → edit header add `jku: https://<Burp Collaborator>/jwks.json` or `x5u` → sign → Forward → check Collaborator for fetch | Headers ignored/allowlisted | Collaborator hit = exploitable |
| 2.3.3b | kid injection | Path traversal / SQLi in `kid` | JWT Editor → set `kid` to `../../../../dev/null`, `kid` with `null`, or SQLi (`' UNION SELECT...`) → sign with known key | kid validated/safe lookup | Bypassed validation |
| 2.3.4 | aud confusion | Replay token across clients/audiences | Repeater: capture token for client A → send to client B's userinfo/API → observe | Strict aud per resource | Accepted cross-audience |
| 2.3.5 | iss / azp validation | Lookalike iss; missing azp | JWT Editor → edit `iss` (trailing slash, case) → re-sign with proper key (if alg confusion not needed, test validation stage) → Forward; replay token w/ wrong `azp` | Exact iss; azp enforced | Lookalike/missing accepted |
| 2.3.6 | PKCE downgrade | Omit/downgrade code_challenge | Intercept authorize request in **Proxy** → delete `code_challenge`/`method` params → Forward; second pass: change `S256`→`plain` and use plaintext verifier | Rejected for public clients | Code issued w/o PKCE/plain |
| 2.3.7 | Code replay/cross-client | Redeem twice / wrong client | Repeater: POST to `/token` with same `code` twice; redeem code with client B's `client_id`+secret | Single-use, client-bound | Reuse/cross-client works |
| 2.3.8 | Token substitution | ID token where access token expected | Repeater: send `Authorization: Bearer <id_token>` to API; reverse (access token to userinfo) | Type/use enforced | Wrong type accepted |
| 2.3.9 | Refresh scope escalation | Request broader scope on refresh | Repeater: refresh grant with `scope=admin:...` beyond original | Scope fixed/limited | Escalated silently |
| 2.3.10 | Refresh replay after revocation | Revoke then reuse | Repeater: POST `/revoke` with refresh token → re-send refresh grant | Family invalidated | Old token valid |
| 2.3.11 | Pre-validation claim processing | Edit claims, observe order-of-ops | Proxy: enable **Intercept → Do intercept → responses**; or intercept request, truncate signature, submit claims-only token → check if claims processed before 401 | Validate-then-process | Claims used pre-validation |
| 2.3.12 | Hybrid flow confusion | Token in query | Check HTTP History for `id_token`/`access_token` in URL (query) of redirect — grep History for `id_token=` | Fragment/POST only | Token in query → logged/stolen |
| 2.3.13 | nonce validation | Remove/wrong nonce | Proxy: intercept callback, or Repeater replay of ID token with wrong/missing `nonce`; remove `nonce` from authorize request → Forward | Required, session-bound | ID token accepted w/o nonce |
| 2.3.14 | userinfo vs ID token | Compare claims | Repeater: call `/userinfo` with access token, decode ID token in JWT Editor → compare `sub` and claims; test if unverified userinfo claims trusted | Consistent, verified | Unverified userinfo trusted |
| 2.3.15 | Exp/clock skew | Expired token; skew abuse | JWT Editor → set `exp` past/future → re-sign correctly (control test) → Forward; also send within server skew window | Enforced, ≤5 min skew | No exp enforcement |

---

## STAGE 3 — FLOW LOGIC VALIDATION

### 3.1 redirect_uri Validation

| # | Test Case | Method | Burp Testing Steps | Pass | Fail |
|---|-----------|--------|--------------------|------|------|
| 3.1.1 | Open redirect | Try hostile hosts | Intercept authorize request → **Match & Replace** or manual edit `redirect_uri` to `https://evil.com`, `https://trusted.com@evil.com`, `https://evil.com?trusted.com` → Forward → watch if browser redirects to attacker with `code` | Exact match only | Code delivered to attacker |
| 3.1.2 | Subdomain bypass | Suffix/subdomain tricks | Repeater/proxy: `https://trusted.com.attacker.com`, `https://sub.trusted.com` → observe redirect Location header | No wildcarding | Subdomain match |
| 3.1.3 | Path tricks | `..`, `@`, `%23` | Proxy edit: `https://trusted.com/../attacker`, `https://trusted.com\@attacker.com`, encoded slashes `%2F`, double-encode `%252F` → Forward → inspect Location | Strict parsing | Parser differential |
| 3.1.4 | Scheme tricks | Custom schemes | Proxy edit: `myapp://evil`, `javascript:alert(1)`, `HTTPS://` case, `https://trusted.com@evil.com` → Forward | Exact scheme+host match | Attacker scheme accepted |
| 3.1.5 | Trailing slash/encoding | `/` variants | Proxy edit: add/remove trailing slash; URL-encode path delimiters → Forward | Byte-exact | Normalization confusion |
| 3.1.6 | Wildcard abuse | Subdomain capture | If `*.trusted.com` registered: use **Burp Collaborator** domain as redirect → receive callback with `code` in History | Wildcards constrained | Collaborator receives code |
| 3.1.7 | Fragment leakage | Token in query | Grep History (`Ctrl+F` in HTTP History) for `access_token=` in URLs; check Referer headers of subsequent requests | Fragment/POST only | Token in URL/logs |
| 3.1.8 | Missing redirect_uri | Omit param | Proxy: delete `redirect_uri` from authorize → Forward → observe redirect Location default | Safe default/Required | Falls back to attacker value |

### 3.2 state Parameter Bypass

| # | Test Case | Method | Burp Testing Steps | Pass | Fail |
|---|-----------|--------|--------------------|------|------|
| 3.2.1 | Missing state | Omit in request/callback | Proxy: delete `state` from authorize request; then delete `state` from callback → Forward each | Rejected | Flow completes |
| 3.2.2 | Not session-bound | Cross-session reuse | Two browsers: capture `state` in session A → replay callback w/ A's state in session B via Repeater/cookie swap (use **Session Handling Rules** or manual Cookie header edit) | State bound to session | Stateless/predictable state (check Decoder: base64 of timestamp = predictable) |
| 3.2.3 | Login CSRF | Force victim login | Capture your own full login flow (attacker acct) → build URL with authorize+state → victim clicks → check victim's session maps to attacker identity via **Autorize** or History inspection | State blocks cross-session login | Login CSRF succeeds |
| 3.2.4 | State replay | Reuse consumed state | Repeater: replay same callback URL+state | Single-use | Replay accepted |

### 3.3 Authorization & Consent Logic

| # | Test Case | Method | Burp Testing Steps | Pass | Fail |
|---|-----------|--------|--------------------|------|------|
| 3.3.1 | Scope escalation | Add scopes pre-consent | Proxy: intercept authorize → add `scope=admin:read` → skip consent → redeem code in Repeater | Downgrade enforced | Silent escalation |
| 3.3.2 | Response type confusion | Change response_type | Proxy edit: `response_type=token` (when code-only), `code token`, downgrade `code id_token`→`code` → Forward | Strict allowlist | Unexpected types honored |
| 3.3.3 | prompt=none abuse | Silent auth | Proxy edit: add `prompt=none` to authorize; test on sensitive action endpoints | Constrained | Silent auth/MFA bypass |
| 3.3.4 | max_age / acr | Weak params | Proxy edit: `max_age=0`, `acr_values=urn:mace:...:password` (low assurance) → Forward | Policy minimums | Step-up bypassed |
| 3.3.5 | Client authentication | No/wrong secret | Repeater: token request without `client_secret`; wrong secret; extract secret from SPA JS via **Search** of site map/JS | Rejected; proper client typing | Secret in JS, auth optional |
| 3.3.6 | Consent bypass | Direct token call | Repeater: skip consent screen URL, call `/token` directly with legit code → check consent record | Server-side consent | Token w/o consent |

### 3.4 SAML Flow Logic

| # | Test Case | Method | Burp Testing Steps | Pass | Fail |
|---|-----------|--------|--------------------|------|------|
| 3.4.1 | IdP-initiated flow | Unsolicited POST | Repeater: craft POST to ACS with valid signed assertion but **no InResponseTo** → send | Disabled/allowlisted | Session created |
| 3.4.2 | ACS confusion | Wrong ACS index | Repeater: change `Destination` + actual POST URL to alternate ACS from metadata | Endpoint validated per metadata | Honored at wrong ACS |
| 3.4.3 | RelayState abuse | Redirect/XSS | Proxy edit: `RelayState=https://evil.com` or `javascript:...`; check response redirect & referer | Allowlisted/opaque | Open redirect/XSS |
| 3.4.4 | AuthnContext downgrade | Strip MFA context | SAML Raider → edit XML remove/change `AuthnContextClassRef` → Re-sign via SAML Raider (imported cert) or pair w/ XSW → Forward | Minimum context enforced | Weaker session created |
| 3.4.5 | Parser differential | Deflate manipulation | Decoder: inflate/deflate assertion; manipulate whitespace between compression and signature check; Repeater send variations | Consistent processing | Differential exploited |

---

## STAGE 4 — SESSION / IDENTITY LIFECYCLE

### 4.1 Single Logout (SLO) Failures

| # | Test Case | Method | Burp Testing Steps | Pass | Fail |
|---|-----------|--------|--------------------|------|------|
| 4.1.1 | SP-initiated SLO | Logout from SP, check all sessions | Proxy: capture logout; send to Repeater; after logout, replay a previous authenticated request of second SP → check 401; test IdP session cookie validity via fresh authorize request | All sessions die | Silent re-auth via IdP cookie |
| 4.1.2 | IdP-initiated SLO | Logout at IdP, check SPs | Logger++: monitor front-channel iframes/redirects to each SP; then Repeater-replay SP session cookie → check validity | All SPs process logout | Zombie sessions |
| 4.1.3 | Back-channel logout | Server-to-server revoke | Logger++: watch for POSTs to `backchannel_logout_uri`/SOAP logout; block front-channel iframes (Proxy intercept drop) → test if session still dies | Session dies regardless | Only browser logout honored |
| 4.1.4 | LogoutRequest spoofing | Forge with victim NameID/SessionIndex | Repeater: capture LogoutRequest → edit `NameID`/`SessionIndex` to another user (from captured traffic) → sign if needed → send | Signed+validated sender | Arbitrary user logout |
| 4.1.5 | LogoutResponse spoofing | Fake success | Repeater: send crafted `LogoutResponse` with Status=Success (no matching request) → check client state | Correlated/validated | Client-side success only |
| 4.1.6 | SLO race | Logout during refresh | Proxy: intercept logout; simultaneously Repeater-send refresh grant before logout completes → then use new access token | Atomic revocation | Post-logout token minted/valid |
| 4.1.7 | SLI / partial state | Mid-flow interruption | Proxy: intercept & drop the ACS/callback POST (never forward) → check for any session/partial state; also drop token response mid-hybrid-flow | Atomic establishment | Partial session usable |

### 4.2 Session Timeout Inconsistencies

| # | Test Case | Method | Burp Testing Steps | Pass | Fail |
|---|-----------|--------|--------------------|------|------|
| 4.2.1 | SP vs IdP mismatch | Compare sessions | Repeater: after SP session expiry, replay SP request; watch for silent 302→IdP→instant re-auth loop (no credentials) → confirm new SP session without user action | SP enforces own re-auth | Silent resurrection |
| 4.2.2 | Idle vs absolute | Test both | Repeater: send requests at idle+1 intervals; keep session alive past absolute ceiling → check hard cut-off | Both enforced | Sliding-only renewal |
| 4.2.3 | Token vs cookie lifetime | Compare expiries | JWT Editor: read `exp`/`iat`; inspect cookie `Max-Age`/`Expires` in response headers (Logger++ filter `Set-Cookie`); test cookie-dead but token-alive scenarios | Consistent lifetimes | Mismatch exploitable |
| 4.2.4 | Clock-skew abuse | Post-expiry window | Repeater: send token in skew window after true exp → note acceptance duration | ≤60s skew | Skew = extension |
| 4.2.5 | Session fixation at SSO | Pre-set session ID | Proxy: note SP cookie pre-auth → complete login → compare cookie value in HTTP History (Match & Replace to force old value) → check if authenticated under old ID | Rotation post-auth | Fixed ID survives |

### 4.3 Revocation & Post-Event Hygiene

| # | Test Case | Method | Burp Testing Steps | Pass | Fail |
|---|-----------|--------|--------------------|------|------|
| 4.3.1 | RFC 7009 revocation | Revoke, test at RS | Repeater: POST `/revoke` with token → immediately replay token at resource server | Immediate denial at RS | RS accepts till exp |
| 4.3.2 | Password change | Change pwd, test tokens | After pwd change, Repeater: replay access token, refresh grant, and session cookie | Global kill | Old sessions live |
| 4.3.3 | De-provisioning | Disable user/MFA | Repeater: use existing tokens after account disable | Immediate invalidation | Tokens valid full TTL |
| 4.3.4 | Token binding | Replay from other origin | Repeater: send token without DPoP proof / from different TLS session → compare | Sender-constrained enforced | Plain bearer from anywhere |

### 4.4 Cookie & Storage Hygiene

| # | Test Case | Method | Burp Testing Steps | Pass | Fail |
|---|-----------|--------|--------------------|------|------|
| 4.4.1 | Cookie flags | Inspect | HTTP History response headers: check `Set-Cookie` for `HttpOnly; Secure; SameSite`; use **Logger++ filter** `Set-Cookie` across all responses; check `Domain` scope | All flags correct | Missing flags |
| 4.4.2 | Token storage | localStorage check | Review JS via site map; intercept XHR — tokens in Authorization header sourced from JS var = in-memory OK; grep JS for `localStorage.setItem` with token | Memory/secure cookie | localStorage tokens |
| 4.4.3 | Logout cleanup | Post-logout state | After logout, Repeater-replay session cookie; check browser storage via app (proxy intercept shows subsequent requests carrying tokens) | Full cleanup | Cookie/storage remains |

---

## Burp Environment Quick Setup

1. **Extensions (BApp Store):** SAML Raider, JWT Editor, Logger++, Autorize, Add custom param (optional).
2. **Match & Replace rules:** Auto-insert `prompt=none`, strip `state`, strip `code_challenge` for quick variant testing (Proxy → Options → Match & Replace).
3. **Session Handling Rules:** For cross-session state tests (3.2.2/3.2.3) — configure a macro to swap cookies between session A/B in Repeater.
4. **Collaborator:** Enable for XXE (2.2.9), `jku/x5u` (2.3.3), redirect_uri capture (3.1.6).
5. **Comparer:** Valid response vs. attack response to confirm session issuance on every XSW variant.
