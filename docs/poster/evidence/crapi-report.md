# Mythos Engagement Report — http://crapi-identity:8080

_Generated 2026-10-25 by mythos-sec. For authorized testing only._

## Summary

| Severity | Count |
|---|---|
| Critical | 0 |
| High | 0 |
| Medium | 0 |
| Low | 2 |
| Info | 0 |
| **Total** | **2** |

**Server:** n/a  
**Technologies:** n/a  

**Tools available:** subfinder, httpx, ffuf, sqlmap, whatweb, nmap

## Findings

### 1. 🔵 Missing Content-Security-Policy

- **Severity:** Low (`CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N`)
- **Asset:** http://crapi-identity:8080
- **Parameter:** `content-security-policy`
- **Confidence:** firm
- **Source:** mythos-engine

The response from http://crapi-identity:8080 does not set the content-security-policy header.

**Evidence:**

```http
GET http://crapi-identity:8080
---
(header absent)
[matched] content-security-policy
```

**Impact:** Without a CSP the impact of an injected script (XSS) is unconstrained.

**Remediation:** Deploy a restrictive Content-Security-Policy.

---

### 2. 🔵 Missing HTTP Strict-Transport-Security

- **Severity:** Low (`CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N`)
- **Asset:** http://crapi-identity:8080
- **Parameter:** `strict-transport-security`
- **Confidence:** firm
- **Source:** mythos-engine

The response from http://crapi-identity:8080 does not set the strict-transport-security header.

**Evidence:**

```http
GET http://crapi-identity:8080
---
(header absent)
[matched] strict-transport-security
```

**Impact:** Users can be downgraded to HTTP and have traffic intercepted.

**Remediation:** Send Strict-Transport-Security with a long max-age on all HTTPS responses.

---
