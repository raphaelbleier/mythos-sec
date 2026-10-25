# Mythos Engagement Report — http://mythos-dvwa

_Generated 2026-10-25 by mythos-sec. For authorized testing only._

## Summary

| Severity | Count |
|---|---|
| Critical | 2 |
| High | 4 |
| Medium | 4 |
| Low | 3 |
| Info | 1 |
| **Total** | **14** |

**Server:** Apache/2.4.25 (Debian)  
**Technologies:** Apache  

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
mxf8d495fex'"<svg/onload=1>
```

**Evidence:**

```http
POST http://mythos-dvwa/vulnerabilities/csp/ [body:include] payload=mxf8d495fex'"<svg/onload=1>
---
ass</h1>

	<div class="vulnerable_code_area">
	<script src='mxf8d495fex'"<svg/onload=1>'></script>

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
mxeb35e815x'"<svg/onload=1>
```

**Evidence:**

```http
GET http://mythos-dvwa/vulnerabilities/xss_r/ [query:name] payload=mxeb35e815x'"<svg/onload=1>
---
"submit" value="Submit">
			</p>

		</form>
		<pre>Hello mxeb35e815x'"<svg/onload=1></pre>
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
mx9409ff0ex'"<svg/onload=1>
```

**Evidence:**

```http
POST http://mythos-dvwa/vulnerabilities/xss_s/ [body:txtName] payload=mx9409ff0ex'"<svg/onload=1>
---
</div>
	<br />

	<div id="guestbook_comments">Name: mx9409ff0ex'"<svg/onload=1><br />Message: test<br /></div>
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
mxf909c3c9x'"<svg/onload=1>
```

**Evidence:**

```http
POST http://mythos-dvwa/vulnerabilities/xss_s/ [body:mtxMessage] payload=mxf909c3c9x'"<svg/onload=1>
---
>

	<div id="guestbook_comments">Name: test<br />Message: mxf909c3c9x'"<svg/onload=1><br /></div>

	<br />

	<h2>Mo
[matched] <svg/onload=1>
```

**Impact:** An attacker can execute arbitrary JavaScript in a victim's browser, stealing sessions or performing actions as the victim.

**Remediation:** Context-aware output encoding; deploy a Content-Security-Policy.

---

### 7. 🟡 Potential IDOR / Broken Object Level Authorization

- **Severity:** Medium (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N`)
- **Asset:** http://mythos-dvwa/security.php#
- **Parameter:** `user_token`
- **Confidence:** tentative
- **Source:** mythos-engine

Changing 'user_token' from 1 to 2 returns a different object while unauthenticated. If these objects belong to different users, this is an authorization flaw.

**Payload / Steps to reproduce:**

```
user_token=1 vs 2
```

**Evidence:**

```http
POST http://mythos-dvwa/security.php# [body:user_token] (user_token=1 then 2)
---
len(1)=5470 vs len(2)=5470
[matched] distinct objects for sequential ids
```

**Impact:** An attacker can read or modify other users' objects by changing an id.

**Remediation:** Enforce per-object authorization on every request; scope queries to the authenticated principal; use unguessable identifiers.

---

### 8. 🟡 Potential IDOR / Broken Object Level Authorization

- **Severity:** Medium (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N`)
- **Asset:** http://mythos-dvwa/setup.php#
- **Parameter:** `user_token`
- **Confidence:** tentative
- **Source:** mythos-engine

Changing 'user_token' from 1 to 2 returns a different object while unauthenticated. If these objects belong to different users, this is an authorization flaw.

**Payload / Steps to reproduce:**

```
user_token=1 vs 2
```

**Evidence:**

```http
POST http://mythos-dvwa/setup.php# [body:user_token] (user_token=1 then 2)
---
len(1)=5522 vs len(2)=5522
[matched] distinct objects for sequential ids
```

**Impact:** An attacker can read or modify other users' objects by changing an id.

**Remediation:** Enforce per-object authorization on every request; scope queries to the authenticated principal; use unguessable identifiers.

---

### 9. 🟡 Potential IDOR / Broken Object Level Authorization

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

### 10. 🟡 phpinfo() information disclosure

- **Severity:** Medium (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`)
- **Asset:** http://mythos-dvwa/phpinfo.php
- **Confidence:** firm
- **Source:** mythos-engine

The path 'phpinfo.php' is reachable and returned HTTP 200.

**Evidence:**

```http
GET http://mythos-dvwa/phpinfo.php
---
HTTP 200, 90103 bytes
[matched] phpinfo.php
```

**Impact:** Sensitive files or metadata exposed to unauthenticated users can leak source code, credentials or internal configuration.

**Remediation:** Remove the file from the web root or restrict access. Ensure VCS metadata and backups are never deployed.

---

### 11. 🔵 Missing Content-Security-Policy

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

### 12. 🔵 Missing HTTP Strict-Transport-Security

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

### 13. 🔵 Missing X-Frame-Options / frame-ancestors

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

### 14. ⚪ Missing X-Content-Type-Options

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
