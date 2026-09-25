# SSO Scanner & Penetration Testing Checklist

A comprehensive toolkit and reference guide for auditing **SAML 2.0**, **OAuth 2.0**, and **OpenID Connect (OIDC)** implementations during penetration tests and security reviews.

---

## 🚀 Components

### 1. Burp Suite Extension (`SSO_Scanner.py`)
A Jython-based extension for Burp Suite that automates passive and active security audits for SAML and OAuth 2.0 / OIDC implementations.

#### Key Features:
- **Passive Scanning**: Automatically inspects traffic for SAML assertions, JWT tokens, OAuth parameters, missing cookie security flags, and unsafe configurations.
- **Active Attacks**:
  - **XML Signature Wrapping (XSW)**: Tests for XSW-1, XSW-3, and signature removal bypasses.
  - **JWT Attacks**: Tests for `alg:none` acceptance and RS256 -> HS256 key confusion attacks.
  - **OAuth & PKCE Checks**: Tests state parameter enforcement, PKCE downgrade, open redirect vulnerabilities on `redirect_uri`, and token/code replay.
- **HTML Reporting**: Generates a complete executive report detailing pass/fail status and evidence for both automated and manual check items.

#### Installation:
1. Configure Burp Suite with the **Jython Standalone JAR** under `Extender > Options > Python Environment`.
2. Go to `Extender > Extensions > Add`.
3. Select `Extension Type: Python` and load `SSO_Scanner.py`.
4. Passive checks will run automatically. Right-click any SAML/OAuth request in Burp to trigger **"Run SSO Active Checks"**.

---

### 2. SSO Penetration Testing Checklist (`checklist.md`)
A detailed 4-stage methodology tailored for manual and semi-automated security testing with Burp Suite:

1. **Stage 1 — Recon**: Endpoint & metadata discovery, cryptographic hygiene, and trust mapping.
2. **Stage 2 — Assertion / Token Analysis**: XML Signature Wrapping (XSW 1–8), SAML assertion manipulation, and OAuth/OIDC JWT vulnerabilities (`alg:none`, RS256->HS256, `jku`/`kid` injection, PKCE enforcement).
3. **Stage 3 — Flow Logic Validation**: `redirect_uri` bypasses, `state` parameter & Login CSRF, response type confusion, and SAML flow logic.
4. **Stage 4 — Session / Identity Lifecycle**: Single Logout (SLO) flaws, session timeout discrepancies, token revocation, and storage security.

👉 View the full guide in [checklist.md](checklist.md).

---

## 🛠️ Burp Suite Environment Setup
To get the most out of the checklist and extension, install the following BApp extensions:
- **SAML Raider** (SAML assertion decoding and XSW test suite)
- **JWT Editor** (JWT token manipulation, signing, key confusion)
- **Logger++** (Enhanced HTTP logging and search filtering)
- **Autorize** (Access control & authorization testing)

---

## 📜 License
MIT License
