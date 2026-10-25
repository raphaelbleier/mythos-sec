# Mythos Engagement Report — http://mythos-dvwa

_Generated 2026-10-25 by mythos-sec. For authorized testing only._

## Summary

| Severity | Count |
|---|---|
| Critical | 2 |
| High | 4 |
| Medium | 2 |
| Low | 13 |
| Info | 1 |
| **Total** | **22** |

**Server:** Apache/2.4.25 (Debian)  
**Technologies:** Apache  

**Tools available:** subfinder, httpx, nuclei, ffuf, sqlmap, nikto, whatweb, nmap

## Findings

### 1. 🔴 SQL Injection (error-based)

- **Severity:** Critical (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`)
- **Asset:** http://mythos-dvwa/vulnerabilities/brute/#
- **Parameter:** `username`
- **Confidence:** firm
- **Source:** mythos-engine

Injecting a quote into 'username' triggers a database error, indicating the input reaches a SQL query unsanitized.

**Payload / Steps to reproduce:**

```
1'"
```

**Evidence:**

```http
GET http://mythos-dvwa/vulnerabilities/brute/# [query:username] payload=1'"
---
<pre>You have an error in your SQL syntax; check the manual that corresponds to your MariaDB server version for the righ
[matched] You have an error in your SQL syntax
```

**Impact:** Full read/write access to the database, authentication bypass, and in many cases remote code execution.

**Remediation:** Use parameterized queries / prepared statements. Never build SQL by string concatenation of user input.

---

### 2. 🔴 SQL Injection (error-based)

- **Severity:** Critical (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`)
- **Asset:** http://mythos-dvwa/vulnerabilities/sqli/#
- **Parameter:** `id`
- **Confidence:** firm
- **Source:** mythos-engine

Injecting a quote into 'id' triggers a database error, indicating the input reaches a SQL query unsanitized.

**Payload / Steps to reproduce:**

```
1'"
```

**Evidence:**

```http
GET http://mythos-dvwa/vulnerabilities/sqli/# [query:id] payload=1'"
---
<pre>You have an error in your SQL syntax; check the manual that corresponds to your MariaDB server version for the righ
[matched] You have an error in your SQL syntax
```

**Impact:** Full read/write access to the database, authentication bypass, and in many cases remote code execution.

**Remediation:** Use parameterized queries / prepared statements. Never build SQL by string concatenation of user input.

---

### 3. 🟠 Reflected Cross-Site Scripting (XSS)

- **Severity:** High (`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`)
- **Asset:** http://mythos-dvwa/vulnerabilities/csp/
- **Parameter:** `include`
- **Confidence:** firm
- **Source:** mythos-engine

The parameter 'include' reflects input into the HTML response without adequate output encoding.

**Payload / Steps to reproduce:**

```
mx6e23afb0x'"<svg/onload=1>
```

**Evidence:**

```http
POST http://mythos-dvwa/vulnerabilities/csp/ [body:include] payload=mx6e23afb0x'"<svg/onload=1>
---
ass</h1>

	<div class="vulnerable_code_area">
	<script src='mx6e23afb0x'"<svg/onload=1>'></script>

<form name="csp" met
[matched] <svg/onload=1>
```

**Impact:** An attacker can execute arbitrary JavaScript in a victim's browser, stealing sessions or performing actions as the victim.

**Remediation:** Context-aware output encoding; deploy a Content-Security-Policy.

---

### 4. 🟠 Reflected Cross-Site Scripting (XSS)

- **Severity:** High (`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`)
- **Asset:** http://mythos-dvwa/vulnerabilities/xss_r/
- **Parameter:** `name`
- **Confidence:** firm
- **Source:** mythos-engine

The parameter 'name' reflects input into the HTML response without adequate output encoding.

**Payload / Steps to reproduce:**

```
mxf0ade395x'"<svg/onload=1>
```

**Evidence:**

```http
GET http://mythos-dvwa/vulnerabilities/xss_r/ [query:name] payload=mxf0ade395x'"<svg/onload=1>
---
"submit" value="Submit">
			</p>

		</form>
		<pre>Hello mxf0ade395x'"<svg/onload=1></pre>
	</div>

	<h2>More Info
[matched] <svg/onload=1>
```

**Impact:** An attacker can execute arbitrary JavaScript in a victim's browser, stealing sessions or performing actions as the victim.

**Remediation:** Context-aware output encoding; deploy a Content-Security-Policy.

---

### 5. 🟠 Reflected Cross-Site Scripting (XSS)

- **Severity:** High (`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`)
- **Asset:** http://mythos-dvwa/vulnerabilities/xss_s/
- **Parameter:** `txtName`
- **Confidence:** firm
- **Source:** mythos-engine

The parameter 'txtName' reflects input into the HTML response without adequate output encoding.

**Payload / Steps to reproduce:**

```
mx0636a065x'"<svg/onload=1>
```

**Evidence:**

```http
POST http://mythos-dvwa/vulnerabilities/xss_s/ [body:txtName] payload=mx0636a065x'"<svg/onload=1>
---
</div>
	<br />

	<div id="guestbook_comments">Name: mx0636a065x'"<svg/onload=1><br />Message: test<br /></div>
[matched] <svg/onload=1>
```

**Impact:** An attacker can execute arbitrary JavaScript in a victim's browser, stealing sessions or performing actions as the victim.

**Remediation:** Context-aware output encoding; deploy a Content-Security-Policy.

---

### 6. 🟠 Reflected Cross-Site Scripting (XSS)

- **Severity:** High (`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`)
- **Asset:** http://mythos-dvwa/vulnerabilities/xss_s/
- **Parameter:** `mtxMessage`
- **Confidence:** firm
- **Source:** mythos-engine

The parameter 'mtxMessage' reflects input into the HTML response without adequate output encoding.

**Payload / Steps to reproduce:**

```
mx7239532bx'"<svg/onload=1>
```

**Evidence:**

```http
POST http://mythos-dvwa/vulnerabilities/xss_s/ [body:mtxMessage] payload=mx7239532bx'"<svg/onload=1>
---
>

	<div id="guestbook_comments">Name: test<br />Message: mx7239532bx'"<svg/onload=1><br /></div>

	<br />

	<h2>Mo
[matched] <svg/onload=1>
```

**Impact:** An attacker can execute arbitrary JavaScript in a victim's browser, stealing sessions or performing actions as the victim.

**Remediation:** Context-aware output encoding; deploy a Content-Security-Policy.

---

### 7. 🟡 Potential IDOR / Broken Object Level Authorization

- **Severity:** Medium (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N`)
- **Asset:** http://mythos-dvwa/vulnerabilities/sqli/#
- **Parameter:** `id`
- **Confidence:** tentative
- **Source:** mythos-engine

Changing 'id' from 1 to 2 returns a different object while unauthenticated. If these objects belong to different users, this is an authorization flaw.

**Payload / Steps to reproduce:**

```
id=1 vs 2
```

**Evidence:**

```http
GET http://mythos-dvwa/vulnerabilities/sqli/# [query:id] (id=1 then 2)
---
len(1)=4538 vs len(2)=4539
[matched] distinct objects for sequential ids
```

**Impact:** An attacker can read or modify other users' objects by changing an id.

**Remediation:** Enforce per-object authorization on every request; scope queries to the authenticated principal; use unguessable identifiers.

---

### 8. 🟡 phpinfo() information disclosure

- **Severity:** Medium (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`)
- **Asset:** http://mythos-dvwa/phpinfo.php
- **Confidence:** firm
- **Source:** mythos-engine

The path 'phpinfo.php' is reachable and returned HTTP 200.

**Evidence:**

```http
GET http://mythos-dvwa/phpinfo.php
---
HTTP 200, 90102 bytes
[matched] phpinfo.php
```

**Impact:** Sensitive files or metadata exposed to unauthenticated users can leak source code, credentials or internal configuration.

**Remediation:** Remove the file from the web root or restrict access. Ensure VCS metadata and backups are never deployed.

---

### 9. 🔵 Missing Content-Security-Policy

- **Severity:** Low (`CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N`)
- **Asset:** http://mythos-dvwa
- **Parameter:** `content-security-policy`
- **Confidence:** firm
- **Source:** mythos-engine

The response from http://mythos-dvwa does not set the content-security-policy header.

**Evidence:**

```http
GET http://mythos-dvwa
---
(header absent)
[matched] content-security-policy
```

**Impact:** Without a CSP the impact of an injected script (XSS) is unconstrained.

**Remediation:** Deploy a restrictive Content-Security-Policy.

---

### 10. 🔵 Missing HTTP Strict-Transport-Security

- **Severity:** Low (`CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N`)
- **Asset:** http://mythos-dvwa
- **Parameter:** `strict-transport-security`
- **Confidence:** firm
- **Source:** mythos-engine

The response from http://mythos-dvwa does not set the strict-transport-security header.

**Evidence:**

```http
GET http://mythos-dvwa
---
(header absent)
[matched] strict-transport-security
```

**Impact:** Users can be downgraded to HTTP and have traffic intercepted.

**Remediation:** Send Strict-Transport-Security with a long max-age on all HTTPS responses.

---

### 11. 🔵 Missing X-Frame-Options / frame-ancestors

- **Severity:** Low (`CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N`)
- **Asset:** http://mythos-dvwa
- **Parameter:** `x-frame-options`
- **Confidence:** firm
- **Source:** mythos-engine

The response from http://mythos-dvwa does not set the x-frame-options header.

**Evidence:**

```http
GET http://mythos-dvwa
---
(header absent)
[matched] x-frame-options
```

**Impact:** The page can be framed by a third party, enabling clickjacking.

**Remediation:** Set X-Frame-Options: DENY or a CSP frame-ancestors directive.

---

### 12. 🔵 Nikto: Configuration information may be available remotely.

- **Severity:** Low
- **Asset:** /config/
- **Confidence:** tentative
- **Source:** nikto

Configuration information may be available remotely.

**Evidence:**

```http
[matched] 000998
```

**Impact:** Server-side misconfiguration or known issue reported by nikto.

**Remediation:** Review the reported item against hardening guidance.

---

### 13. 🔵 Nikto: Apache default file found.

- **Severity:** Low
- **Asset:** /icons/README
- **Confidence:** tentative
- **Source:** nikto

Apache default file found.

**Evidence:**

```http
[matched] 003584
```

**Impact:** Server-side misconfiguration or known issue reported by nikto.

**Remediation:** Review the reported item against hardening guidance.

---

### 14. 🔵 Nikto: Admin login page/section found.

- **Severity:** Low
- **Asset:** /login.php
- **Confidence:** tentative
- **Source:** nikto

Admin login page/section found.

**Evidence:**

```http
[matched] 006333
```

**Impact:** Server-side misconfiguration or known issue reported by nikto.

**Remediation:** Review the reported item against hardening guidance.

---

### 15. 🔵 Nikto: .gitignore file found. It is possible to grasp the directory structure.

- **Severity:** Low
- **Asset:** /.gitignore
- **Confidence:** tentative
- **Source:** nikto

.gitignore file found. It is possible to grasp the directory structure.

**Evidence:**

```http
[matched] 007224
```

**Impact:** Server-side misconfiguration or known issue reported by nikto.

**Remediation:** Review the reported item against hardening guidance.

---

### 16. 🔵 Nikto: X-Frame-Options header is deprecated and was replaced with the Content-Security-

- **Severity:** Low
- **Asset:** /
- **Confidence:** tentative
- **Source:** nikto

X-Frame-Options header is deprecated and was replaced with the Content-Security-Policy HTTP header with the frame-ancestors directive.

**Evidence:**

```http
[matched] 007342
```

**Impact:** Server-side misconfiguration or known issue reported by nikto.

**Remediation:** Review the reported item against hardening guidance.

---

### 17. 🔵 Nikto: The X-Content-Type-Options header is not set. This could allow the user agent to

- **Severity:** Low
- **Asset:** /
- **Confidence:** tentative
- **Source:** nikto

The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type.

**Evidence:**

```http
[matched] 007352
```

**Impact:** Server-side misconfiguration or known issue reported by nikto.

**Remediation:** Review the reported item against hardening guidance.

---

### 18. 🔵 Nikto: Suggested security header missing: permissions-policy.

- **Severity:** Low
- **Asset:** /
- **Confidence:** tentative
- **Source:** nikto

Suggested security header missing: permissions-policy.

**Evidence:**

```http
[matched] 013587
```

**Impact:** Server-side misconfiguration or known issue reported by nikto.

**Remediation:** Review the reported item against hardening guidance.

---

### 19. 🔵 Nikto: Apache/2.4.25 appears to be outdated (current is at least 2.4.68).

- **Severity:** Low
- **Asset:** /
- **Confidence:** tentative
- **Source:** nikto

Apache/2.4.25 appears to be outdated (current is at least 2.4.68).

**Evidence:**

```http
[matched] 600050
```

**Impact:** Server-side misconfiguration or known issue reported by nikto.

**Remediation:** Review the reported item against hardening guidance.

---

### 20. 🔵 Nikto: Directory indexing found.

- **Severity:** Low
- **Asset:** /config/
- **Confidence:** tentative
- **Source:** nikto

Directory indexing found.

**Evidence:**

```http
[matched] 750500
```

**Impact:** Server-side misconfiguration or known issue reported by nikto.

**Remediation:** Review the reported item against hardening guidance.

---

### 21. 🔵 Nikto: Directory indexing found.

- **Severity:** Low
- **Asset:** /docs/
- **Confidence:** tentative
- **Source:** nikto

Directory indexing found.

**Evidence:**

```http
[matched] 750500
```

**Impact:** Server-side misconfiguration or known issue reported by nikto.

**Remediation:** Review the reported item against hardening guidance.

---

### 22. ⚪ Missing X-Content-Type-Options

- **Severity:** Info (`CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N`)
- **Asset:** http://mythos-dvwa
- **Parameter:** `x-content-type-options`
- **Confidence:** firm
- **Source:** mythos-engine

The response from http://mythos-dvwa does not set the x-content-type-options header.

**Evidence:**

```http
GET http://mythos-dvwa
---
(header absent)
[matched] x-content-type-options
```

**Impact:** Browsers may MIME-sniff responses, enabling some injection attacks.

**Remediation:** Set X-Content-Type-Options: nosniff.

---
