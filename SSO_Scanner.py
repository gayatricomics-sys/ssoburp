# -*- coding: utf-8 -*-
"""
=====================================================================
 SSO Scanner - SAML / OAuth 2.0 / OpenID Connect  (Burp Jython Ext)
=====================================================================
 Author  : SSO Pentest Toolkit
 Requires: Burp Suite + Jython 2.7 standalone JAR
 Install : Extender > Extensions > Add > Extension type: Python
           > select this file. (Passive checks run automatically.)
 Active  : Right-click any SAML/OAuth request in any Burp tool >
           "Run SSO Active Checks".
 Report  : Click "Save HTML Report" on the SSO Scanner tab.
           Every test case shows CHECKED (PASS/FAIL) or UNCHECKED.
=====================================================================
"""

from burp import (IBurpExtender, IHttpListener, ITab, IContextMenuFactory,
                  IParameter)
from javax.swing import (JPanel, JTable, JScrollPane, JButton, JLabel,
                         JFileChooser, JOptionPane, BoxLayout, JTextField, JMenuItem)
from javax.swing.table import DefaultTableModel
from java.awt import BorderLayout, FlowLayout, Dimension
from java.util import ArrayList
from java.util.zip import Inflater, Deflater
from java.io import (ByteArrayInputStream, ByteArrayOutputStream,
                     File, FileOutputStream, OutputStreamWriter)
from javax.xml.parsers import DocumentBuilderFactory
from javax.xml.transform import TransformerFactory, OutputKeys
from javax.xml.transform.dom import DOMSource
from javax.xml.transform.stream import StreamResult
from java.security import KeyFactory
from java.security.spec import RSAPublicKeySpec
from java.math import BigInteger
from java.lang import Thread, Runnable
from javax.swing import SwingUtilities
import base64, re, json, time, hmac, hashlib, datetime
import jarray

SAML_NS  = "urn:oasis:names:tc:SAML:2.0:assertion"
SAMLP_NS = "urn:oasis:names:tc:SAML:2.0:protocol"
JWT_RE   = re.compile(r'eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*')

STAGE_TITLES = {"1": "Stage 1 - Recon",
                "2": "Stage 2 - Assertion/Token Analysis",
                "3": "Stage 3 - Flow Logic Validation",
                "4": "Stage 4 - Session/Identity Lifecycle"}

# Full test-case catalogue (report lists every case: Checked or Unchecked)
CATALOG = [
 ("1.1.1","Enumerate SSO endpoints"),("1.1.2","SAML metadata inspection"),
 ("1.1.3","OIDC discovery: implicit flows disabled"),("1.1.4","Fingerprint implementation"),
 ("1.2.1","Signing algorithm audit (no SHA-1/DSA/none)"),("1.2.2","Key management / JWKS hygiene"),
 ("1.3.1","SP/IdP trust relationship mapping"),("1.3.2","Token grant inventory (no legacy grants)"),
 ("XSW-1","XML Signature Wrapping variant 1"),("XSW-2","XML Signature Wrapping variant 2"),
 ("XSW-3","XML Signature Wrapping variant 3"),("XSW-4","XML Signature Wrapping variant 4"),
 ("XSW-5","XML Signature Wrapping variant 5"),("XSW-6","XML Signature Wrapping variant 6"),
 ("XSW-7","XML Signature Wrapping variant 7"),("XSW-8","XML Signature Wrapping variant 8"),
 ("2.2.1","SAML signature mandatory"),("2.2.2","AudienceRestriction validated"),
 ("2.2.3","InResponseTo validated / no replay"),("2.2.4","Conditions NotBefore/NotOnOrAfter enforced"),
 ("2.2.5","Recipient/Destination validated"),("2.2.6","SubjectConfirmationData validated"),
 ("2.2.7","Attributes/NameID cannot be escalated"),("2.2.8","Assertion replay rejected (single-use)"),
 ("2.2.9","No XXE/DTD in SAML parser"),
 ("2.3.1","JWT RS256->HS256 algorithm confusion rejected"),
 ("2.3.2","JWT alg=none rejected"),("2.3.3","jku/x5u/kid header injection rejected"),
 ("2.3.4","Token audience (aud) strictly validated"),("2.3.5","Issuer (iss)/azp validated"),
 ("2.3.6","PKCE enforced (no downgrade)"),("2.3.7","Auth code single-use & client-bound"),
 ("2.3.8","Token type substitution rejected"),("2.3.9","Refresh token scope escalation rejected"),
 ("2.3.10","Refresh token replay after revocation rejected"),
 ("2.3.11","Claims read only after signature validation"),
 ("2.3.12","Hybrid flow token handling (no query leakage)"),
 ("2.3.13","OIDC nonce required, session-bound"),("2.3.14","Userinfo vs ID-token consistency"),
 ("2.3.15","JWT exp/nbf enforced with sane skew"),
 ("3.1.1","redirect_uri: no open redirect"),("3.1.2","redirect_uri: no subdomain bypass"),
 ("3.1.3","redirect_uri: no path tricks"),("3.1.4","redirect_uri: scheme tricks rejected"),
 ("3.1.5","redirect_uri: trailing slash/encoding exact"),("3.1.6","No wildcard redirect abuse"),
 ("3.1.7","No tokens in URL query strings"),("3.1.8","redirect_uri omission safe"),
 ("3.2.1","state parameter required"),("3.2.2","state session-bound/unpredictable"),
 ("3.2.3","Login CSRF blocked"),("3.2.4","state single-use"),
 ("3.3.1","No scope escalation"),("3.3.2","response_type strict allowlist"),
 ("3.3.3","prompt=none constrained"),("3.3.4","max_age/acr policy enforced"),
 ("3.3.5","Client authentication enforced, no secrets in JS"),
 ("3.3.6","Consent enforced server-side"),
 ("3.4.1","IdP-initiated (unsolicited) disabled/allowlisted"),
 ("3.4.2","ACS endpoint strictly validated"),("3.4.3","RelayState validated"),
 ("3.4.4","AuthnContext minimum enforced"),("3.4.5","No parser differential"),
 ("4.1.1","SP-initiated SLO kills all sessions"),
 ("4.1.2","IdP-initiated SLO kills all SP sessions"),
 ("4.1.3","Back-channel logout honored"),
 ("4.1.4","LogoutRequest spoofing rejected"),
 ("4.1.5","LogoutResponse spoofing rejected"),
 ("4.1.6","No SLO/refresh race"),
 ("4.1.7","No partial login state"),
 ("4.2.1","SP vs IdP timeout consistency"),
 ("4.2.2","Idle + absolute timeouts enforced"),
 ("4.2.3","Token vs cookie lifetime consistency"),
 ("4.2.4","Clock skew minimal"),
 ("4.2.5","Session ID rotation at SSO boundary"),
 ("4.3.1","RFC 7009 revocation honored at RS"),
 ("4.3.2","Password change kills SSO sessions"),
 ("4.3.3","De-provisioning kills tokens immediately"),
 ("4.3.4","Sender-constrained tokens (DPoP/mTLS)"),
 ("4.4.1","Cookie flags (HttpOnly/Secure/SameSite)"),
 ("4.4.2","No tokens in browser storage (localStorage)"),
 ("4.4.3","Logout cleanup complete"),
]

# ---------------------------------------------------------------- utils
def b64u_dec(s):
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)

def b64u_enc(b):
    return base64.urlsafe_b64encode(b).rstrip("=")

def esc(s):
    return str(s).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")


class BurpExtender(IBurpExtender, IHttpListener, ITab, IContextMenuFactory):

    # ---------------------------------------------------------- register
    def registerExtenderCallbacks(self, callbacks):
        self._cb   = callbacks
        self._h    = callbacks.getHelpers()
        self._rows = []                 # list of dicts
        self._idx  = {}                 # (checkid,target) -> row dict
        self._jwks = {}                 # host -> (n_b64, e_b64)
        self._disc = {}                 # issuer -> dict
        self._rsa  = {}                 # issuer -> (pem_bytes, der_bytes)
        self._lock = time.time()

        callbacks.setExtensionName("SSO Scanner (SAML/OAuth/OIDC)")
        callbacks.registerHttpListener(self)
        callbacks.registerContextMenuFactory(self)

        # ---------------- UI
        self.tab = JPanel(BorderLayout())
        top = JPanel(FlowLayout(FlowLayout.LEFT))
        title = JLabel("SSO Scanner - passive checks are live. "
                       "Right-click a SAML/OAuth request > 'Run SSO Active Checks'.")
        btnRep  = JButton("Save HTML Report", actionPerformed=self.save_report)
        btnClr  = JButton("Clear Results",     actionPerformed=self.clear_all)
        top.add(title); top.add(btnRep); top.add(btnClr)
        self.model = DefaultTableModel(
            ["Check ID","Test Case","Target","Status","Detail"], 0) {
            "isCellEditable": lambda r,c: False }
        self.table = JTable(self.model)
        self.table.setAutoCreateRowSorter(True)
        self.table.getColumnModel().getColumn(4).setPreferredWidth(500)
        sp = JScrollPane(self.table)
        sp.setPreferredSize(Dimension(1100, 550))
        self.tab.add(top, BorderLayout.NORTH)
        self.tab.add(sp, BorderLayout.CENTER)
        callbacks.addSuiteTab(self)
        callbacks.printOutput("[SSO Scanner] Loaded. Passive scanning active.")
        return

    # ---------------------------------------------------------- helpers
    def add_result(self, cid, name, target, status, detail):
        key = (cid, target)
        if key in self._idx:
            row = self._idx[key]
            if row["status"] == "FAIL" and status != "FAIL":
                return
            row.update(status=status, detail=detail)
            def _upd():
                i = self._rows.index(row)
                self.model.setValueAt(status, i, 3)
                self.model.setValueAt(detail, i, 4)
            SwingUtilities.invokeLater(_upd)
            return
        row = {"id":cid,"name":name,"target":target,"status":status,"detail":detail}
        self._rows.append(row); self._idx[key] = row
        def _add():
            self.model.addRow([cid, name, target, status, detail])
        SwingUtilities.invokeLater(_add)

    def saml_inflate_decode(self, val):
        try:
            raw = self._h.base64Decode(val)
            inf = Inflater(True)
            inf.setInput(raw, 0, len(raw))
            buf = jarray.zeros(65536, 'b'); out = ByteArrayOutputStream()
            while not inf.finished():
                n = inf.inflate(buf)
                if n <= 0 and inf.needsInput(): break
                out.write(buf, 0, n)
            inf.end()
            return out.toString("UTF-8")
        except Exception:
            return None

    def saml_deflate_encode(self, xml):
        data = xml.encode("UTF-8")
        d = Deflater(Deflater.DEFLATED, True)
        d.setInput(data, 0, len(data)); d.finish()
        buf = jarray.zeros(8192, 'b'); out = ByteArrayOutputStream()
        while not d.finished():
            out.write(buf, 0, d.deflate(buf))
        d.end()
        return self._h.base64Encode(out.toByteArray())

    def parse_xml(self, s):
        dbf = DocumentBuilderFactory.newInstance()
        dbf.setNamespaceAware(True)
        try: dbf.setFeature(
            "http://apache.org/xml/features/disallow-doctype-decl", True)
        except Exception: pass
        return dbf.newDocumentBuilder().parse(
            ByteArrayInputStream(s.encode("UTF-8")))

    def serialize(self, node):
        t = TransformerFactory.newInstance().newTransformer()
        t.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes")
        ba = ByteArrayOutputStream()
        t.transform(DOMSource(node), StreamResult(ba))
        return ba.toString("UTF-8")

    def doc_get(self, doc, ns, local):
        return doc.getElementsByTagNameNS(ns, local)

    def get_headers_map(self, respInfo):
        hm = {}
        for h in respInfo.getHeaders():
            k, _, v = h.partition(":")
            hm.setdefault(k.strip().lower(), []).append(v.strip())
        return hm

    def rebuild_req(self, req, old, new):
        s = self._h.bytesToString(req)
        if old not in s: return None
        s = s.replace(old, new)
        i = s.find("\r\n\r\n")
        if i < 0: return None
        head = [x for x in s[:i].split("\r\n")
                if not x.lower().startswith("content-length:")]
        return self._h.buildHttpMessage(
            head, self._h.stringToBytes(s[i+4:]))

    def fire(self, msg, newreq):
        rr = self._cb.makeHttpRequest(msg.getHttpService(), newreq)
        resp = rr.getResponse()
        if resp is None: return None, None
        return resp, self._h.analyzeResponse(resp)

    def gives_session(self, respInfo):
        if respInfo is None: return False
        if respInfo.getStatusCode() not in (200, 302): return False
        for h in respInfo.getHeaders():
            if h.lower().startswith("set-cookie:"):
                return True
        return False

    # ================================================= PASSIVE SCANNER
    def processHttpMessage(self, toolFlag, isRequest, msg):
        try:
            if isRequest: self.scan_request(msg)
            else:         self.scan_response(msg)
        except Exception as e:
            self._cb.printError("[SSO] passive error: %s" % e)

    # ---------------- request side
    def scan_request(self, msg):
        req  = msg.getRequest()
        info = self._h.analyzeRequest(msg.getHttpService(), req)
        url  = info.getUrl().toString()
        host = info.getUrl().getHost()
        low  = url.lower()
        is_authorize = ("response_type=" in low or "/authorize" in low
                        or "/auth" in low)
        is_token_ep  = "grant_type=" in low or "/token" in low

        params = info.getParameters()
        seen = {}
        for p in params:
            seen[p.getName()] = p

        # ----- SAMLResponse passive
        if "SAMLResponse" in seen:
            val = seen["SAMLResponse"].getValue()
            xml = self.saml_inflate_decode(val)
            if xml:
                try: self.passive_saml(xml, host, url)
                except Exception as e:
                    self.add_result("2.2.1","SAML signature mandatory",
                        host,"ERROR","parse: %s" % e)

        # ----- OAuth authorize checks
        if is_authorize:
            if "state" not in seen:
                self.add_result("3.2.1","state parameter required",
                    host,"FAIL","authorize request has no state param: %s" % url)
            else:
                st = seen["state"].getValue()
                pred = bool(re.match(r'^[0-9]+$', st)) or len(st) < 8
                self.add_result("3.2.1","state parameter required",
                    host,"PASS","state present")
                if pred:
                    self.add_result("3.2.2","state session-bound/unpredictable",
                        host,"FAIL","state looks predictable: %s" % st[:24])
                else:
                    self.add_result("3.2.2","state session-bound/unpredictable",
                        host,"PASS","state high-entropy")
            if "code_challenge" not in seen:
                self.add_result("2.3.6","PKCE enforced (no downgrade)",
                    host,"FAIL","no code_challenge in authorize (public client?)")
            else:
                m = seen["code_challenge_method"].getValue() \
                    if "code_challenge_method" in seen else "plain"
                if m.lower() == "plain":
                    self.add_result("2.3.6","PKCE enforced (no downgrade)",
                        host,"FAIL","code_challenge_method=plain")
                else:
                    self.add_result("2.3.6","PKCE enforced (no downgrade)",
                        host,"PASS","S256 challenge present")
            if "redirect_uri" in seen:
                ru = seen["redirect_uri"].getValue()
                if not ru.startswith("https://"):
                    self.add_result("3.1.4","redirect_uri scheme tricks rejected",
                        host,"FAIL","non-HTTPS redirect_uri: %s" % ru)
                elif "*" in ru:
                    self.add_result("3.1.6","No wildcard redirect abuse",
                        host,"FAIL","wildcard in redirect_uri: %s" % ru)
                else:
                    self.add_result("3.1.4","redirect_uri scheme tricks rejected",
                        host,"PASS","HTTPS redirect_uri")
            if "response_type" in seen:
                rt = seen["response_type"].getValue()
                if "token" in rt:
                    self.add_result("3.3.2","response_type strict allowlist",
                        host,"FAIL","implicit/hybrid token flow enabled: %s" % rt)
                else:
                    self.add_result("3.3.2","response_type strict allowlist",
                        host,"PASS","response_type=%s" % rt)

        # ----- token endpoint grants
        if is_token_ep and "grant_type" in seen:
            g = seen["grant_type"].getValue()
            if g == "password":
                self.add_result("1.3.2","Token grant inventory",
                    host,"FAIL","Resource Owner Password grant enabled")
            else:
                self.add_result("1.3.2","Token grant inventory",
                    host,"INFO","grant observed: %s" % g)

        # ----- JWT in parameters
        for p in params:
            for m in JWT_RE.findall(p.getValue() or ""):
                self.passive_jwt(m, host, url)

        # ----- JWT in Authorization header
        for h in info.getHeaders():
            if h.lower().startswith("authorization: bearer "):
                tok = h.split(None, 2)[-1].strip()
                if JWT_RE.match(tok):
                    self.passive_jwt(tok, host, url)

    # ---------------- response side
    def scan_response(self, msg):
        resp = msg.getResponse()
        if resp is None: return
        info = self._h.analyzeResponse(resp)
        url  = self._h.analyzeRequest(msg.getHttpService(),
                                      msg.getRequest()).getUrl().toString()
        host = self._h.analyzeRequest(msg.getHttpService(),
                                      msg.getRequest()).getUrl().getHost()
        hm   = self.get_headers_map(info)
        body = self._h.bytesToString(resp[info.getBodyOffset():])
        low  = url.lower()

        # cookies
        for sc in hm.get("set-cookie", []):
            misses = []
            if "httponly" not in sc.lower(): misses.append("HttpOnly")
            if "secure"   not in sc.lower(): misses.append("Secure")
            ss = re.search(r'samesite\s*=\s*(\w+)', sc, re.I)
            if not ss: misses.append("SameSite")
            name = sc.split("=")[0].strip()
            if misses:
                self.add_result("4.4.1","Cookie flags",
                    host,"FAIL","cookie '%s' missing: %s" % (name, ",".join(misses)))
            else:
                self.add_result("4.4.1","Cookie flags",
                    host,"PASS","cookie '%s' flags OK" % name)

        # tokens in query string
        if re.search(r'[?&](access_token|id_token)=', url):
            self.add_result("3.1.7","No tokens in URL query strings",
                host,"FAIL","token in query string: %s" % url[:140])

        # tokens in redirect Location query
        for loc in hm.get("location", []):
            if re.search(r'[?&](access_token|id_token)=', loc):
                self.add_result("2.3.12","Hybrid flow token handling",
                    host,"FAIL","token in Location query: %s" % loc[:140])

        # client_secret in JS/JSON
        ct = " ".join(hm.get("content-type", [])).lower()
        if ("javascript" in ct or "json" in ct) and "html" not in ct:
            if re.search(r'"?client_secret"?\s*[:=]\s*"[^"]+"', body):
                self.add_result("3.3.5",
                    "Client auth enforced, no secrets in JS",
                    host,"FAIL","client_secret exposed in body of %s" % url[:100])

        # discovery document
        if low.endswith("/.well-known/openid-configuration"):
            try:
                cfg = json.loads(body)
                self._disc[cfg.get("issuer", host)] = cfg
                rts = " ".join(cfg.get("response_types_supported", []))
                if "token" in rts or "id_token" in rts:
                    self.add_result("1.1.3",
                        "OIDC discovery: implicit flows disabled",
                        host,"FAIL","discovery exposes implicit response types")
                else:
                    self.add_result("1.1.3",
                        "OIDC discovery: implicit flows disabled",
                        host,"PASS","no implicit flows advertised")
            except Exception as e:
                self.add_result("1.1.3",
                    "OIDC discovery: implicit flows disabled",
                    host,"ERROR","JSON parse: %s" % e)

        # JWKS cache
        if ("/jwks" in low or "certs" in low or low.endswith("/keys")) \
           and "json" in ct:
            try:
                j = json.loads(body)
                for k in j.get("keys", []):
                    if k.get("kty") == "RSA" and "n" in k:
                        self._jwks[host] = (k["n"], k.get("e","AQAB"))
                        break
            except Exception:
                pass

    # ---------------- passive SAML checks
    def passive_saml(self, xml, host, url):
        if "<!DOCTYPE" in xml.upper():
            self.add_result("2.2.9","No XXE/DTD in SAML parser",
                host,"FAIL","DOCTYPE present in assertion")
        else:
            self.add_result("2.2.9","No XXE/DTD in SAML parser",
                host,"PASS","no DTD")
        doc = self.parse_xml(xml)

        sigs = self.doc_get(doc, "*", "Signature")
        if sigs.length == 0:
            self.add_result("2.2.1","SAML signature mandatory",
                host,"FAIL","no Signature element in assertion/response")
        else:
            self.add_result("2.2.1","SAML signature mandatory",
                host,"PASS","Signature present")
            sx = self.serialize(sigs.item(0))
            if "sha1" in sx.lower():
                self.add_result("1.2.1",
                    "Signing algorithm audit (no SHA-1/DSA/none)",
                    host,"FAIL","SignatureMethod uses SHA-1")
            else:
                self.add_result("1.2.1",
                    "Signing algorithm audit (no SHA-1/DSA/none)",
                    host,"PASS","strong signature algorithm")

        aud = self.doc_get(doc, SAML_NS, "Audience")
        if aud.length == 0:
            self.add_result("2.2.2","AudienceRestriction validated",
                host,"FAIL","no AudienceRestriction element")
        else:
            val = aud.item(0).getTextContent().strip()
            if host in val or val == host:
                self.add_result("2.2.2","AudienceRestriction validated",
                    host,"PASS","audience matches host")
            else:
                self.add_result("2.2.2","AudienceRestriction validated",
                    host,"FAIL","audience '%s' != host '%s'" % (val, host))

        scd = self.doc_get(doc, SAML_NS, "SubjectConfirmationData")
        ir2 = None
        if scd.length:
            ir2 = scd.item(0).getAttribute("InResponseTo")
        if not ir2:
            root = doc.getDocumentElement()
            ir2 = root.getAttribute("InResponseTo")
        if ir2:
            self.add_result("2.2.3","InResponseTo validated / no replay",
                host,"PASS","InResponseTo present")
        else:
            self.add_result("2.2.3","InResponseTo validated / no replay",
                host,"INFO","unsolicited assertion (IdP-initiated?) - verify policy")

        conds = self.doc_get(doc, SAML_NS, "Conditions")
        ok = False; detail = ""
        if conds.length:
            c = conds.item(0)
            nba = c.getAttribute("NotBefore"); noa = c.getAttribute("NotOnOrAfter")
            if noa:
                ok = True
                try:
                    exp = datetime.datetime.strptime(noa[:19], "%Y-%m-%dT%H:%M:%S")
                    if exp < datetime.datetime.utcnow():
                        ok = False; detail = "NotOnOrAfter in the past"
                    elif (exp - datetime.datetime.utcnow()).total_seconds() > 600:
                        detail = "long validity (%ds)" % (exp - datetime.datetime.utcnow()).total_seconds()
                except Exception: pass
            else:
                detail = "Conditions missing NotOnOrAfter"
        else:
            detail = "no Conditions element"
        self.add_result("2.2.4","Conditions NotBefore/NotOnOrAfter enforced",
            host, "PASS" if ok else "FAIL", detail or "validity window OK")

        scd2 = self.doc_get(doc, SAML_NS, "SubjectConfirmationData")
        rec = False
        if scd2.length and scd2.item(0).getAttribute("Recipient"):
            rec = True
        dest = doc.getDocumentElement().getAttribute("Destination")
        if rec or dest:
            self.add_result("2.2.5","Recipient/Destination validated",
                host,"PASS","Recipient/Destination present")
        else:
            self.add_result("2.2.5","Recipient/Destination validated",
                host,"FAIL","no Recipient or Destination")

    # ---------------- passive JWT checks
    def passive_jwt(self, tok, host, url):
        try:
            parts = tok.split(".")
            hdr = json.loads(b64u_dec(parts[0]))
            pay = json.loads(b64u_dec(parts[1]))
        except Exception:
            return
        alg = hdr.get("alg", "")
        looks_id = ("nonce" in pay) or ("at_hash" in pay) or ("iss" in pay and "aud" in pay)

        if alg.lower() == "none":
            self.add_result("2.3.2","JWT alg=none rejected",
                host,"FAIL","token with alg=none observed")
        elif not alg:
            self.add_result("2.3.2","JWT alg=none rejected",
                host,"FAIL","token missing alg header")
        elif alg.startswith("HS") and looks_id:
            self.add_result("2.3.1","JWT RS256->HS256 confusion rejected",
                host,"INFO","symmetric alg %s on identity token (verify key mgmt)" % alg)
        else:
            self.add_result("2.3.2","JWT alg=none rejected",
                host,"PASS","alg=%s" % alg)

        if "exp" not in pay:
            self.add_result("2.3.15","JWT exp/nbf enforced with sane skew",
                host,"FAIL","no exp claim")
        else:
            ttl = pay["exp"] - int(time.time())
            if ttl > 86400:
                self.add_result("2.3.15","JWT exp/nbf enforced with sane skew",
                    host,"FAIL","very long token TTL (%dh)" % (ttl/3600))
            else:
                self.add_result("2.3.15","JWT exp/nbf enforced with sane skew",
                    host,"PASS","TTL %ds" % ttl)

        if looks_id:
            if "aud" not in pay:
                self.add_result("2.3.4","Token audience (aud) strictly validated",
                    host,"FAIL","ID token missing aud")
            else:
                self.add_result("2.3.4","Token audience (aud) strictly validated",
                    host,"PASS","aud present")
            if "iss" not in pay:
                self.add_result("2.3.5","Issuer (iss)/azp validated",
                    host,"FAIL","ID token missing iss")
            else:
                self.add_result("2.3.5","Issuer (iss)/azp validated",
                    host,"PASS","iss=%s" % pay["iss"])
            if "nonce" not in pay:
                self.add_result("2.3.13","OIDC nonce required, session-bound",
                    host,"FAIL","ID token missing nonce")
            else:
                self.add_result("2.3.13","OIDC nonce required, session-bound",
                    host,"PASS","nonce present")

    # ================================================= ACTIVE (menu)
    def createMenuItems(self, invocation):
        msgs = invocation.getSelectedMessages()
        if not msgs: return None
        items = ArrayList()
        item = JMenuItem(
            "Run SSO Active Checks",
            actionPerformed=lambda e, m=msgs: self.run_active_async(m))
        items.add(item)
        return items

    def run_active_async(self, msgs):
        t = Thread(Runnable() {
            "run": lambda: [self.run_active(m) for m in msgs] })
        t.start()

    def run_active(self, msg):
        try:
            req  = msg.getRequest()
            info = self._h.analyzeRequest(msg.getHttpService(), req)
            host = info.getUrl().getHost()
            params = {p.getName(): p for p in info.getParameters()}

            if "SAMLResponse" in params:
                xml = self.saml_inflate_decode(params["SAMLResponse"].getValue())
                if xml:
                    self.active_saml(msg, host, xml)
            # JWT active
            for p in params.values():
                for tok in JWT_RE.findall(p.getValue() or ""):
                    self.active_jwt(msg, host, tok); break
            for h in info.getHeaders():
                if h.lower().startswith("authorization: bearer "):
                    tok = h.split(None, 2)[-1].strip()
                    if JWT_RE.match(tok):
                        self.active_jwt(msg, host, tok)
            # OAuth active
            if "response_type=" in info.getUrl().toString().lower() or "/authorize" in info.getUrl().toString().lower():
                self.active_authorize(msg, host, params)
            # replay for ACS / token
            if "SAMLResponse" in params or "grant_type" in params:
                self.active_replay(msg, host)
        except Exception as e:
            self._cb.printError("[SSO] active error: %s" % e)

    # ---------------- active SAML
    def active_saml(self, msg, host, xml):
        base_resp = msg.getResponse()
        base_info = self._h.analyzeResponse(base_resp) if base_resp else None
        base_ok   = base_info is not None and base_info.getStatusCode() in (200, 302)
        if not base_ok:
            self.add_result("XSW-1","XML Signature Wrapping variant 1",
                host,"ERROR","baseline request did not succeed; skipped")
            return
        orig_doc = self.parse_xml(xml)

        # XSW-3: duplicate assertion
        try:
            doc = self.parse_xml(xml)
            asrts = self.doc_get(doc, SAML_NS, "Assertion")
            if asrts.length:
                a0 = asrts.item(0)
                clone = a0.cloneNode(True)
                sigs = clone.getElementsByTagNameNS("*", "Signature")
                while sigs.length:
                    clone.removeChild(sigs.item(0))
                avs = clone.getElementsByTagNameNS(SAML_NS, "AttributeValue")
                if avs.length:
                    avs.item(0).setTextContent("admin")
                a0.getParentNode().insertBefore(clone, a0.getNextSibling())
                self.try_saml_variant(msg, host, doc, "XSW-3",
                    "XML Signature Wrapping variant 3",
                    "unsigned modified duplicate assertion processed")
        except Exception as e:
            self.add_result("XSW-3","XML Signature Wrapping variant 3",
                host,"ERROR",str(e))

        # XSW-1: new Response wrapper (unsigned modified first, signed original second)
        try:
            impl  = orig_doc.getImplementation()
            ndoc  = impl.createDocument(None, "samlp:Response", None)
            nroot = ndoc.getDocumentElement()
            oroot = orig_doc.getDocumentElement()
            for i in range(oroot.getAttributes().getLength()):
                a = oroot.getAttributes().item(i)
                nroot.setAttribute(a.getNodeName(), a.getValue())
            nroot.setAttribute("ID", (oroot.getAttribute("ID") or "resp") + "_xsw1")
            # modified unsigned clone
            src = self.doc_get(orig_doc, SAML_NS, "Assertion").item(0)
            mod = src.cloneNode(True)
            ms = mod.getElementsByTagNameNS("*", "Signature")
            while ms.length: mod.removeChild(ms.item(0))
            mav = mod.getElementsByTagNameNS(SAML_NS, "AttributeValue")
            if mav.length: mav.item(0).setTextContent("admin")
            nroot.appendChild(ndoc.importNode(mod, True))
            nroot.appendChild(ndoc.importNode(src, True))
            self.try_saml_variant(msg, host, ndoc, "XSW-1",
                "XML Signature Wrapping variant 1",
                "wrapped: modified unsigned assertion processed")
        except Exception as e:
            self.add_result("XSW-1","XML Signature Wrapping variant 1",
                host,"ERROR",str(e))

        # Signature removal
        try:
            doc = self.parse_xml(xml)
            s = self.doc_get(doc, "*", "Signature")
            while s.length:
                n = s.item(0); n.getParentNode().removeChild(n)
            self.try_saml_variant(msg, host, doc, "2.2.1-ACT",
                "SAML signature mandatory",
                "assertion accepted after signature removal")
        except Exception as e:
            self.add_result("2.2.1-ACT","SAML signature mandatory",
                host,"ERROR",str(e))

        # Audience tamper + sig strip (negative control)
        try:
            doc = self.parse_xml(xml)
            aud = self.doc_get(doc, SAML_NS, "Audience")
            if aud.length:
                aud.item(0).setTextContent("https://invalid-aud.example/")
                s = self.doc_get(doc, "*", "Signature")
                while s.length:
                    n = s.item(0); n.getParentNode().removeChild(n)
                self.try_saml_variant(msg, host, doc, "2.2.2-ACT",
                    "AudienceRestriction validated",
                    "tampered audience accepted")
        except Exception as e:
            pass

    def try_saml_variant(self, msg, host, doc, cid, name, fail_detail):
        xml = self.serialize(doc)
        enc = self.saml_deflate_encode(xml)
        req = msg.getRequest()
        info = self._h.analyzeRequest(msg.getHttpService(), req)
        sparam = None
        for p in info.getParameters():
            if p.getName() == "SAMLResponse":
                sparam = p; break
        if sparam is None: return
        newp = self._h.buildParameter("SAMLResponse", enc, IParameter.PARAM_BODY)
        newreq = self._h.updateParameter(req, newp)
        resp, ri = self.fire(msg, newreq)
        if ri is None:
            self.add_result(cid, name, host, "ERROR", "no response")
            return
        if self.gives_session(ri):
            self.add_result(cid, name, host, "FAIL", fail_detail)
        else:
            self.add_result(cid, name, host, "PASS",
                "rejected (%d)" % ri.getStatusCode())

    # ---------------- active JWT
    def active_jwt(self, msg, host, tok):
        parts = tok.split(".")
        if len(parts) < 2: return
        hdr_s, pay_s = parts[0], parts[1]
        try:
            pay = json.loads(b64u_dec(pay_s))
            hdr = json.loads(b64u_dec(hdr_s))
        except Exception: return
        resp0 = msg.getResponse()
        if resp0 is None: return
        st0 = self._h.analyzeResponse(resp0).getStatusCode()
        if st0 not in (200, 201):
            self.add_result("2.3.2","JWT alg=none rejected",
                host,"INFO","baseline not 200 (%d); skipped active JWT checks" % st0)
            return

        # alg=none
        try:
            forged = (b64u_enc(json.dumps({"alg":"none","typ":"JWT"}))
                      + "." + pay_s + ".")
            newreq = self.rebuild_req(msg.getRequest(), tok, forged)
            if newreq:
                resp, ri = self.fire(msg, newreq)
                if ri and ri.getStatusCode() == st0:
                    self.add_result("2.3.2","JWT alg=none rejected",
                        host,"FAIL","alg=none token accepted (same %d response)" % st0)
                elif ri:
                    self.add_result("2.3.2","JWT alg=none rejected",
                        host,"PASS","alg=none rejected (%d)" % ri.getStatusCode())
        except Exception as e:
            self.add_result("2.3.2","JWT alg=none rejected", host,"ERROR",str(e))

        # RS256 -> HS256 confusion using public key as HMAC secret
        try:
            if hdr.get("alg","").startswith("RS") or hdr.get("alg","").startswith("ES"):
                keys = self.get_rsa_keys(pay.get("iss"), host)
                if keys:
                    pem, der = keys
                    hnew = b64u_enc(json.dumps({"alg":"HS256","typ":"JWT"}))
                    msgb = (hnew + "." + pay_s).encode()
                    for mat, lab in ((pem,"PEM"), (der,"DER")):
                        sig = b64u_enc(hmac.new(mat, msgb, hashlib.sha256).digest())
                        forged = hnew + "." + pay_s + "." + sig
                        newreq = self.rebuild_req(msg.getRequest(), tok, forged)
                        if not newreq: continue
                        resp, ri = self.fire(msg, newreq)
                        if ri and ri.getStatusCode() == st0:
                            self.add_result("2.3.1",
                                "JWT RS256->HS256 algorithm confusion rejected",
                                host,"FAIL",
                                "HS256-with-%s-key accepted -> algorithm confusion" % lab)
                            break
                    else:
                        self.add_result("2.3.1",
                            "JWT RS256->HS256 algorithm confusion rejected",
                            host,"PASS","confusion attempts rejected")
                else:
                    self.add_result("2.3.1",
                        "JWT RS256->HS256 algorithm confusion rejected",
                        host,"NOT TESTED","JWKS unavailable; run passive browsing first")
        except Exception as e:
            self.add_result("2.3.1",
                "JWT RS256->HS256 algorithm confusion rejected", host,"ERROR",str(e))

    def get_rsa_keys(self, iss, host):
        iss = (iss or "").rstrip("/")
        if iss in self._rsa: return self._rsa[iss]
        jwks_uri = None
        if iss in self._disc:
            jwks_uri = self._disc[iss].get("jwks_uri")
        elif host in self._jwks:
            n, e = self._jwks[host]
        else:
            try:
                if iss:
                    path = "/" + iss.split("//", 1)[-1].split("/", 1)[1] \
                           if "/" in iss.split("//", 1)[-1] else "/.well-known/openid-configuration"
                    hh = iss.split("//")[-1].split("/")[0]
                    svc = self._h.buildHttpService(hh, 443, True)
                    r = self._cb.makeHttpRequest(svc,
                        self._h.buildHttpMessage(["GET %s HTTP/1.1" % path,
                            "Host: %s" % hh, "Connection: close"], None))
                    if r.getResponse():
                        b = self._h.bytesToString(
                            r.getResponse()[self._h.analyzeResponse(
                                r.getResponse()).getBodyOffset():])
                        cfg = json.loads(b); self._disc[iss] = cfg
                        jwks_uri = cfg.get("jwks_uri")
            except Exception:
                return None
        try:
            if jwks_uri:
                h = jwks_uri.split("//")[-1].split("/")[0]
                rest = jwks_uri.split("//")[-1].split("/")[1:]
                path = "/" + "/".join(rest) if rest else "/"
                svc = self._h.buildHttpService(h, 443, True)
                r = self._cb.makeHttpRequest(svc,
                    self._h.buildHttpMessage(["GET %s HTTP/1.1" % path,
                        "Host: %s" % h, "Connection: close"], None))
                if r.getResponse():
                    b = self._h.bytesToString(
                        r.getResponse()[self._h.analyzeResponse(
                            r.getResponse()).getBodyOffset():])
                    for k in json.loads(b).get("keys", []):
                        if k.get("kty") == "RSA":
                            self._jwks[h] = (k["n"], k.get("e","AQAB"))
                            break
            hh = jwks_uri.split("//")[-1].split("/")[0] if jwks_uri else host
            if hh not in self._jwks and host not in self._jwks:
                return None
            n, e = self._jwks.get(hh, self._jwks.get(host))
            nb = b64u_dec(n); eb = b64u_dec(e)
            spec = RSAPublicKeySpec(BigInteger(1, nb), BigInteger(1, eb))
            pub = KeyFactory.getInstance("RSA").generatePublic(spec)
            der = pub.getEncoded()
            pem = ("-----BEGIN PUBLIC KEY-----\n"
                   + base64.encodestring(der).replace("\n","")
                   + "\n-----END PUBLIC KEY-----").encode()
            self._rsa[iss] = (pem, der)
            return self._rsa[iss]
        except Exception:
            return None

    # ---------------- active OAuth authorize
    def active_authorize(self, msg, host, params):
        req = msg.getRequest()
        # state removal
        if "state" in params:
            try:
                newreq = self._h.removeParameter(req, params["state"])
                resp, ri = self.fire(msg, newreq)
                loc = ""
                if ri:
                    for h in ri.getHeaders():
                        if h.lower().startswith("location:"):
                            loc = h.split(":",1)[1]
                if "code=" in loc or "id_token" in loc:
                    self.add_result("3.2.1-ACT","state parameter required",
                        host,"FAIL","code/token issued without state")
                elif ri:
                    self.add_result("3.2.1-ACT","state parameter required",
                        host,"PASS","missing state rejected (%d)" % ri.getStatusCode())
            except Exception as e:
                self.add_result("3.2.1-ACT","state parameter required",
                    host,"ERROR",str(e))
        # PKCE removal
        if "code_challenge" in params:
            try:
                newreq = self._h.removeParameter(req, params["code_challenge"])
                if "code_challenge_method" in params:
                    newreq = self._h.removeParameter(newreq, params["code_challenge_method"])
                resp, ri = self.fire(msg, newreq)
                loc = ""
                if ri:
                    for h in ri.getHeaders():
                        if h.lower().startswith("location:"):
                            loc = h.split(":",1)[1]
                if "code=" in loc:
                    self.add_result("2.3.6-ACT","PKCE enforced (no downgrade)",
                        host,"FAIL","authorization code issued without PKCE")
                elif ri:
                    self.add_result("2.3.6-ACT","PKCE enforced (no downgrade)",
                        host,"PASS","PKCE removal rejected")
            except Exception as e:
                self.add_result("2.3.6-ACT","PKCE enforced (no downgrade)",
                    host,"ERROR",str(e))
        # open redirect probe
        if "redirect_uri" in params:
            try:
                evil = "https://sso-scanner.invalid/callback"
                newp = self._h.buildParameter("redirect_uri", evil,
                                              IParameter.PARAM_URL)
                newreq = self._h.updateParameter(req, newp)
                resp, ri = self.fire(msg, newreq)
                loc = ""
                if ri:
                    for h in ri.getHeaders():
                        if h.lower().startswith("location:"):
                            loc = h.split(":",1)[1].strip()
                if loc.startswith(evil):
                    self.add_result("3.1.1-ACT","redirect_uri: no open redirect",
                        host,"FAIL","redirect to unregistered URI %s" % evil)
                elif ri:
                    self.add_result("3.1.1-ACT","redirect_uri: no open redirect",
                        host,"PASS","unregistered redirect_uri rejected")
            except Exception as e:
                self.add_result("3.1.1-ACT","redirect_uri: no open redirect",
                    host,"ERROR",str(e))

    # ---------------- replay
    def active_replay(self, msg, host):
        try:
            resp, ri = self.fire(msg, msg.getRequest())
            if ri is None: return
            req_info = self._h.analyzeRequest(msg.getHttpService(), msg.getRequest())
            names = [p.getName() for p in req_info.getParameters()]
            if "SAMLResponse" in names:
                if self.gives_session(ri):
                    self.add_result("2.2.8",
                        "Assertion replay rejected (single-use)",
                        host,"FAIL","replayed assertion created a session")
                else:
                    self.add_result("2.2.8",
                        "Assertion replay rejected (single-use)",
                        host,"PASS","replay rejected")
            elif "grant_type" in names and ri.getStatusCode() == 200:
                self.add_result("2.3.7",
                    "Auth code single-use & client-bound",
                    host,"FAIL","token endpoint replay returned 200")
            elif "grant_type" in names:
                self.add_result("2.3.7",
                    "Auth code single-use & client-bound",
                    host,"PASS","replay rejected (%d)" % ri.getStatusCode())
        except Exception as e:
            self.add_result("2.2.8","Assertion replay rejected (single-use)",
                host,"ERROR",str(e))

    # ================================================= REPORT
    def save_report(self, event=None):
        ch = JFileChooser()
        ch.setSelectedFile(File("sso_scan_report.html"))
        if ch.showSaveDialog(self.tab) != JFileChooser.APPROVE_OPTION:
            return
        f = ch.getSelectedFile()
        try:
            w = OutputStreamWriter(FileOutputStream(f), "UTF-8")
            w.write(self.build_report())
            w.close()
            JOptionPane.showMessageDialog(
                self.tab, "Report saved to %s" % f.getAbsolutePath())
        except Exception as e:
            JOptionPane.showMessageDialog(self.tab, "Error: %s" % e)

    def clear_all(self, event=None):
        self._rows = []; self._idx = {}
        self.model.setRowCount(0)

    def getTabCaption(self): return "SSO Scanner"
    def getUiComponent(self): return self.tab

    def build_report(self):
        done  = [r for r in self._rows]
        fcnt  = len([r for r in done if r["status"] == "FAIL"])
        pcnt  = len([r for r in done if r["status"] == "PASS"])
        icnt  = len([r for r in done if r["status"] in ("INFO","ERROR")])
        checked_ids = set(r["id"].split("-")[0] for r in done)

        h = []
        h.append("<html><head><meta charset='utf-8'><title>SSO Pentest Report</title>")
        h.append("<style>body{font-family:Segoe UI,Arial;margin:32px;color:#222}"
                 "h1{font-size:24px}h2{font-size:18px;margin-top:28px;border-bottom:2px solid #444;padding-bottom:4px}"
                 "table{border-collapse:collapse;width:100%;font-size:13px}"
                 "td,th{border:1px solid #bbb;padding:6px 8px;vertical-align:top;text-align:left}"
                 "th{background:#333;color:#fff}"
                 ".PASS{background:#dff0d8}.FAIL{background:#f2dede}"
                 ".INFO{background:#fcf8e3}.NOT{background:#eee;color:#777}"
                 ".summary span{padding:4px 12px;border-radius:4px;margin-right:8px}"
                 ".legend{font-size:12px;color:#555;margin-top:8px}</style></head><body>")
        h.append("<h1>SSO Penetration Test Report</h1>")
        h.append("<p>Generated by Burp SSO Scanner &middot; %s</p>"
                 % datetime.datetime.now().strftime("%Y-%m-%d %H:%M"))
        h.append("<div class='summary'>")
        h.append("<span class='PASS'>CHECKED - PASS: %d</span>" % pcnt)
        h.append("<span class='FAIL'>CHECKED - FAIL: %d</span>" % fcnt)
        h.append("<span class='INFO'>CHECKED - INFO/ERROR: %d</span>" % icnt)
        h.append("<span class='NOT'>UNCHECKED (manual): %d</span>"
                 % (len(CATALOG) - len(checked_ids)))
        h.append("</div>")
        h.append("<div class='legend'>CHECKED = test executed by the scanner with a verdict. "
                 "UNCHECKED = requires manual verification (active multi-step flows, XSW variants 2/4-8, "
                 "SLO/session lifecycle tests).</div>")

        cur_stage = None
        h.append("<table><tr><th>Check ID</th><th>Test Case</th><th>Checked?</th>"
                 "<th>Result</th><th>Target</th><th>Evidence</th></tr>")
        for cid, name in CATALOG:
            stg = cid.split(".")[0]
            if cid.startswith("XSW"): stg = "2"
            if stg != cur_stage:
                cur_stage = stg
                h.append("<tr><td colspan='6' style='background:#555;color:#fff'>"
                         "<b>%s</b></td></tr>" % STAGE_TITLES.get(stg, stg))
            rows = [r for r in done if r["id"].split("-")[0] == cid]
            if rows:
                for r in rows:
                    h.append("<tr class='%s'><td>%s</td><td>%s</td><td>Yes</td>"
                             "<td><b>%s</b></td><td>%s</td><td>%s</td></tr>"
                             % (r["status"], cid, esc(name), r["status"],
                                esc(r["target"]), esc(r["detail"])))
            else:
                h.append("<tr class='NOT'><td>%s</td><td>%s</td><td>No</td>"
                         "<td>UNCHECKED</td><td>-</td><td>Manual verification required</td></tr>"
                         % (cid, esc(name)))
        h.append("</table>")
        h.append("<p style='margin-top:24px;font-size:12px;color:#888'>"
                 "This report supports, but does not replace, manual verification of "
                 "multi-step and stateful flows.</p></body></html>")
        return "".join(h)
