# Mythos Engagement Report — http://mythos-vampi:5000

_Generated 2026-10-25 by mythos-sec. For authorized testing only._

## Summary

| Severity | Count |
|---|---|
| Critical | 0 |
| High | 1 |
| Medium | 0 |
| Low | 3 |
| Info | 1 |
| **Total** | **5** |

**Server:** Werkzeug/2.2.3 Python/3.11.15  
**Technologies:** Flask/Werkzeug  

**Tools available:** subfinder, httpx, katana, ffuf, sqlmap, whatweb, nmap

## Findings

### 1. 🟠 Sensitive data exposure in API response

- **Severity:** High (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`)
- **Asset:** http://mythos-vampi:5000/users/v1/_debug
- **Confidence:** firm
- **Source:** mythos-engine

The endpoint returns JSON containing sensitive fields (password) to the caller.

**Evidence:**

```http
GET http://mythos-vampi:5000/users/v1/_debug
---
{
  "users": [
    {
      "admin": false,
      "email": "mail1@mail.com",
      "password": "***",
      "username": "name1"
    },
    {
      "admin": false,
      "email": "mail2@mail.com",
      "password": "***",
      "username": "name2"
    },
    {
      "admin": true,
      "email": "admin@mail.com",
      "password": "***",
      "username": "admin"
    }
  ]
}
[matched] 3 sensitive field(s): password
```

**Impact:** Credentials, tokens or secrets are disclosed, enabling account takeover or lateral movement.

**Remediation:** Never return secret fields in API responses; scope data to the authenticated principal; remove debug/dump endpoints from production.

---

### 2. 🔵 Missing Content-Security-Policy

- **Severity:** Low (`CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N`)
- **Asset:** http://mythos-vampi:5000
- **Parameter:** `content-security-policy`
- **Confidence:** firm
- **Source:** mythos-engine

The response from http://mythos-vampi:5000 does not set the content-security-policy header.

**Evidence:**

```http
GET http://mythos-vampi:5000
---
(header absent)
[matched] content-security-policy
```

**Impact:** Without a CSP the impact of an injected script (XSS) is unconstrained.

**Remediation:** Deploy a restrictive Content-Security-Policy.

---

### 3. 🔵 Missing HTTP Strict-Transport-Security

- **Severity:** Low (`CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N`)
- **Asset:** http://mythos-vampi:5000
- **Parameter:** `strict-transport-security`
- **Confidence:** firm
- **Source:** mythos-engine

The response from http://mythos-vampi:5000 does not set the strict-transport-security header.

**Evidence:**

```http
GET http://mythos-vampi:5000
---
(header absent)
[matched] strict-transport-security
```

**Impact:** Users can be downgraded to HTTP and have traffic intercepted.

**Remediation:** Send Strict-Transport-Security with a long max-age on all HTTPS responses.

---

### 4. 🔵 Missing X-Frame-Options / frame-ancestors

- **Severity:** Low (`CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N`)
- **Asset:** http://mythos-vampi:5000
- **Parameter:** `x-frame-options`
- **Confidence:** firm
- **Source:** mythos-engine

The response from http://mythos-vampi:5000 does not set the x-frame-options header.

**Evidence:**

```http
GET http://mythos-vampi:5000
---
(header absent)
[matched] x-frame-options
```

**Impact:** The page can be framed by a third party, enabling clickjacking.

**Remediation:** Set X-Frame-Options: DENY or a CSP frame-ancestors directive.

---

### 5. ⚪ Missing X-Content-Type-Options

- **Severity:** Info (`CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N`)
- **Asset:** http://mythos-vampi:5000
- **Parameter:** `x-content-type-options`
- **Confidence:** firm
- **Source:** mythos-engine

The response from http://mythos-vampi:5000 does not set the x-content-type-options header.

**Evidence:**

```http
GET http://mythos-vampi:5000
---
(header absent)
[matched] x-content-type-options
```

**Impact:** Browsers may MIME-sniff responses, enabling some injection attacks.

**Remediation:** Set X-Content-Type-Options: nosniff.

---
