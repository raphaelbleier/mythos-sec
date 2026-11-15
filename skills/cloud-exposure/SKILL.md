---
name: cloud-exposure
description: Cloud, Kubernetes and serverless exposure reachable from the web surface - object storage permissions (S3, GCS, Azure Blob with and without SAS), public write shown from the policy or the ACL without ever writing, presigned-URL and SAS hygiene, Lambda function URLs and API Gateway authorizer gaps, Cloud Run and Azure Functions front doors, unauthenticated kubelet, Dashboard, etcd, cAdvisor, Docker API, Consul and Nomad, and the cloud credentials a client bundle publishes. Use when recon finds a bucket or blob host, a presigned URL, a *.lambda-url.on.aws / execute-api / run.app / cloudfunctions.net / azurewebsites.net endpoint, a Firebase or Supabase config, or an orchestrator port.
---

# Cloud exposure: read-only, scope-gated, and never confirmed here

Everything in this skill is **GET, HEAD or OPTIONS**. `scripts/cloudexp` contains
no PUT, POST or DELETE at all, which is why "the bucket allows anonymous write"
is read off the bucket policy or the ACL rather than demonstrated with an
upload. If neither is readable, the answer is `inconclusive` and the finding
says what proving it would have needed. That is not caution for its own sake: a
test object in someone else's bucket is data you created in their account, and
AGENTS.md refuses it.

Two rules that shape every step below.

**A cloud endpoint is a third party, and a request to it is a request you made.**
`<bucket>.s3.amazonaws.com`, `storage.googleapis.com`,
`<account>.blob.core.windows.net`, `<id>.execute-api.<region>.amazonaws.com` are
hosts that must be in `engagements/<dir>/scope.yaml` before you touch them.
`cloudexp` checks every destination *before* opening the socket, skips what the
scope does not name, and lists it under `refused`. **A bucket the target's page
links is not in scope because the page links it** — a `<img>` pointing at
`vendor-cdn-assets.s3.amazonaws.com` is a vendor's bucket, and probing it is
testing a company nobody authorized you to test. Report the name as a candidate
destination and leave it refused unless the operator adds it in an editor.

**You may not write `confirmed`.** Every verdict here is `candidate` with the
recorded request/response pair, or `inconclusive` where the permission shape is
ambiguous. From outside, a 403 from a bucket policy, a 403 from an organization
SCP and a 403 from S3 Block Public Access are the same three bytes.

Playbook: `knowledge/web/baas-cloud-storage.md` (confirmation standard, the
three-principal RLS test, presigned-URL tampering, and the scope rule for a
third party's bucket). Metadata: `knowledge/web/ssrf.md`.

## Steps

Signatures below are from `scripts/cloudexp <sub> --help`. `--json` works on
every subcommand, before or after the subcommand name. Exit code 1 means at
least one `candidate`; 0 means nothing worth a human's time; 2 is usage.

1. **Harvest the footprint from the page, not from a guess.**

       scripts/cloudexp harvest <url> [--max-assets 20] [--json]

   Fetches the entry point, then its stylesheets, scripts and source maps, and
   pulls every bucket, container, serverless front door, presigned URL and
   cloud credential out of them *and out of the response headers*. Each
   candidate records which document named it, so `sources: [sourcemap:/static/
   app.js.map]` tells you the name was stripped from the shipped bundle and
   survived in `sourcesContent`. **Contacts:** the target's origin and the
   origins of those assets. Nothing it finds is contacted. Write the JSON to
   the engagement directory: the next three steps read it.

2. **Decide which harvested names are yours.** For each one, ask whether
   `scope.yaml` names its host. It usually does not. Record the ones you are
   leaving alone, by name, in `recon.md` — an unprobed vendor bucket is a
   decision, and an unexplained gap in the report is not.

3. **Classify object-storage permissions, per permission, not per bucket.**

       scripts/cloudexp buckets <name>... [--provider {azure,gcs,s3}]
           [--endpoint URL] [--region REGION] [--key KEY] [--sas SAS]
           [--wordlist FILE] [--allow-sweep] [--max-names 20] [--json]

   Azure names are `account/container` (or the full
   `<account>.blob.core.windows.net/<container>`); R2 and DigitalOcean Spaces
   speak the S3 API including its error bodies, so leave `--provider` off and
   let it infer. The output has one row per permission with the IAM resource it
   tests, and the distinction is the point:

   * `list` is `s3:ListBucket` on `arn:aws:s3:::bucket`
   * `get-object` is `s3:GetObject` on `arn:aws:s3:::bucket/*`

   A policy that grants `GetObject` on `bucket/*` and no `ListBucket` hands an
   attacker every object whose key they can guess while a listing-only check
   calls the bucket secure. Never report "the bucket is readable" off a
   successful listing: read the `get-object` row. Without `--key` the probe
   reuses the first key a successful listing returned, which is why the lab's
   `mythos-lab-public` lists fine and `--key private.txt` still comes back
   `denied`.

   On Azure, run it twice: once anonymously and once with `--sas '<query string
   of a SAS the operator was issued>'`. That is the control that separates
   "anonymous access is off" from "the container does not exist" — both answer
   `AuthenticationFailed`. A listing that only worked with your own SAS is the
   control working, and `cloudexp` reports it as *not* a finding.

4. **Read public write, never write it.** Step 3 already did: if `?policy` is
   readable it looks for a `Statement` with `Effect: Allow`, `Principal: "*"`
   and a `s3:Put*`/`s3:Delete*`/`s3:*` action; if `?acl` is readable it looks
   for the `AllUsers` (or `AuthenticatedUsers`) `WRITE` grant. On GCS it reads
   the bucket IAM policy for `allUsers` bound to a write role. On Azure it does
   not claim anything, because the public access level is not readable from
   outside and the SAS's permissions are in the SAS's own `sp` (step 5). Where
   the policy and the ACL are both denied, `public_write` is `null` with the
   reason — that is the honest answer, and a test upload is not an alternative.

5. **Presigned URL and SAS hygiene — offline first.**

       scripts/cloudexp presigned <url>... [--probe] [--json]

   Only URLs **the operator's own account was issued**. Replaying someone
   else's presigned URL is using a credential. Offline it reports the flavour
   (SigV4, SigV2, GCS V4, Azure SAS), the signing scope out of
   `X-Amz-Credential` (key id, date, region, service), the absolute expiry and
   the seconds left, the signed-header set, `sp`/`se`/`si` for a SAS, and
   whether a session token makes the URL die with the role session whatever the
   expiry says. Three things it will tell you that get mis-reported:

   * **Extension is not a bypass.** The expiry is part of the string to sign in
     SigV4, SigV2 and a SAS, so editing it yields `SignatureDoesNotMatch` or
     `AuthenticationFailed`. The finding is the lifetime the signer *chose* —
     an `X-Amz-Expires` of 604800 on a document URL is a week of unrevocable
     access — not that you could edit it.
   * **Truncation is the real test.** `--probe` sends four read-only arms
     (baseline, swapped object key, raised expiry, one signed parameter
     removed) as `GET` with `Range: bytes=0-0`, because the question is whether
     the signature is accepted and the object's bytes are not yours to pull. An
     arm that is accepted while the baseline also works is a signer that does
     not verify the whole signed set: a `candidate`.
   * **The URL leaks by construction.** The credential is in the query string,
     so it is in access logs, in browser history, and in the `Referer` of any
     cross-origin subresource a page embedding it requests unless that page
     sends `Referrer-Policy: no-referrer` or `same-origin`. Step 1 already told
     you whether the URL is in the page or in a bundle — that is the leak,
     already happened, and it is what the finding should lead with.

6. **Serverless front doors and the authorizer gap.**

       scripts/cloudexp serverless <url>...
           [--kind {lambda-url,api-gateway,cloud-run,cloud-functions,azure-functions,workers}]
           [--stages prod,dev] [--json]

   The host shape is the fingerprint; `--kind` overrides it for a custom domain
   or for the lab. Read the answers with the platform's own vocabulary, because
   the words are not interchangeable:

   * **Lambda function URL** has exactly two auth types. `AuthType NONE`
     answers an unsigned request and is on the internet for everyone; `AWS_IAM`
     returns `403 {"Message":"Forbidden"}`. There is no API key and no
     authorizer in between. `x-amzn-RequestId` on the response proves the answer
     came from Lambda rather than from a proxy in front of it.
   * **API Gateway REST API** says `Missing Authentication Token` for a path the
     stage does not have — that is a **missing route, not a guard**, and
     reporting it as "authentication required" is the standard mistake.
     `Forbidden` is an API key or a resource policy; `Unauthorized` is a Lambda
     or Cognito authorizer doing its job.
   * **API Gateway HTTP API** says `Not Found` when no route matches, and a
     `$default` route makes it answer *every* path, so one unguarded route is
     every path. The `default-route` arm (a path that cannot exist) tells the
     two API types apart.
   * One stage open while another is guarded is the finding: pass
     `--stages prod,dev` when the operator knows the stage names. There is no
     default list, because guessing stage names at a third party is a sweep.
   * **Cloud Run / Cloud Functions**: anonymous `403 "Your client does not have
     permission to get URL"` is `--no-allow-unauthenticated` working; anything
     under 400 is `allUsers` on the invoker role.
   * **Azure Functions**: authorization *is* the `?code=` key. A function key
     opens one function, a host key opens every function in the app, the master
     key opens the admin API — and a key in the client bundle means the
     function has no authorization at all. Step 7 finds the key; do not use it
     against anything but the operator's own function.

7. **Orchestrator exposure, one read-only path per daemon.**

       scripts/cloudexp orchestrator <host> [--only name,name] [--endpoint URL]
           [--json]

   `--only` takes any of: `kubelet-readonly`, `kubelet-readonly-metrics`,
   `kubelet-authenticated`, `kubelet-healthz`, `kube-apiserver`,
   `kube-apiserver-http`, `dashboard`, `etcd`, `etcd-metrics`, `cadvisor`,
   `docker-api`, `docker-api-tls`, `consul`, `consul-ui`, `nomad`,
   `nomad-status`. Each probe is one GET with a fingerprint, so "something
   answers on 2379" and "etcd answers on 2379" are different verdicts: a status
   under 400 whose fingerprint does not match is `inconclusive`, not a find.
   `401`/`403` is recorded as the *correct* answer and is not a finding.
   What matters per daemon:

   * `kubelet-readonly` (10255) `/pods` returning a `PodList` is every pod on
     the node with its environment and its service-account mounts, with no
     authentication by design. Off by default since Kubernetes 1.10, so if it
     answers, someone turned it on.
   * `kubelet-authenticated` (10250) returning a `PodList` instead of `401` is
     `anonymous-auth=true`, which is worse, because `/run` and `/exec` are on
     the same port. `cloudexp` does not touch those.
   * `/metrics` and `/healthz` disclose the version (`kubernetes_build_info`),
     which is what `scripts/cvefeed match` needs next.
   * `etcd` `/version` is read-only and reads no key — every Secret in the
     cluster is in etcd in plaintext unless encryption at rest is on, so
     reachability is the whole finding.
   * `docker-api` (2375) `/version` answering is root on the host:
     `/containers/create` is one POST away, and that POST is not in this file.
   * Consul's default ACL policy is allow and Nomad's ACLs are off by default,
     so a reachable agent is the service catalogue, the KV store, or job
     submission.

   Every host:port goes through the scope check. A node that is obviously part
   of the target's cluster but whose IP the scope file does not name is refused
   and listed.

8. **Cloud metadata through the application: hand off, do not reimplement.**

       scripts/cloudexp metadata [<url> <parameter>] [--json]

   Sends nothing. It prints the per-provider request table — read live out of
   `scripts/ssrfprobe`'s own `METADATA`, not a second copy — and the exact
   command to run. Then run that command:

       scripts/ssrfprobe probe <url> <parameter> --oast <in-scope-oast-host>
       scripts/ssrfprobe metadata <url> <parameter>

   `ssrfprobe` owns this surface because the impact question is about the
   *primitive*, not the path: it measures method control and header control as
   separate facts first. IMDSv1 needs a plain GET, so a URL-only SSRF reaches
   it; IMDSv2 needs a `PUT /latest/api/token` and the token back in a request
   header, so it needs both controls, and a PUT carrying `X-Forwarded-For` is
   rejected while the default hop limit of 1 drops anything proxied. GCP denies
   everything without `Metadata-Flavor: Google`, Azure needs `Metadata: true`
   and no `X-Forwarded-For`, Oracle's `/opc/v2/` needs
   `Authorization: Bearer Oracle` while `/opc/v1/` needs nothing, and Alibaba
   and DigitalOcean need nothing at all. Header control therefore decides four
   of the six. Never write "cloud credentials reachable" off a callback alone.

9. **Credentials in the client, and what each one can actually do.**

       scripts/cloudexp clientcreds <dir|url> [--max-files 400] [--json]

   The generic credential regexes are `scripts/clientside`'s, called directly —
   there is one secret scanner in this repository. This adds the
   provider-specific meaning, and the column that matters is `by_design`:

   * **by design, not a finding on its own**: a Google/Firebase `AIza…` API key
     (the finding is an *unrestricted* key — no referrer or app restriction, so
     someone else's site bills the project), a whole `firebaseConfig` (the
     finding is the Realtime Database / Firestore / Storage rules), a Supabase
     anon key (the finding is the row-level-security policy), a Cognito
     user-pool id (the finding is open self-signup, or an identity pool with
     unauthenticated identities and a wide role).
   * **not by design**: an `AKIA…` IAM user key, a service-account JSON
     (`"type":"service_account"` — a private key, critical on sight), an Azure
     Functions `?code=`, a SAS with `w`/`c`/`a` in `sp`, and a Supabase JWT
     whose payload decodes to `role: service_role`, which bypasses RLS on every
     table.
   * For a key that is not by design: report the **presence** and stop. "Tried
     it to prove it works" is using a credential.
   * For a key that is by design: the finding is the rule behind it, proven per
     `knowledge/web/baas-cloud-storage.md` — three principals, the agent's own
     rows, a `Content-Range` count as the proof, never a row dump.

10. **Write the verdict.** `verdicts/<slug>.md` with `state: candidate` and the
    recorded pair, or `tested` naming the classes you ran, or `skipped` with the
    reason — "the bucket belongs to a third party and the scope file does not
    name it" is a good reason and belongs in the report. Put the refused
    destination list in `recon.md` verbatim. A `candidate` goes to
    `candidates/<id>.md` with the request and response bytes the validator
    replays; the validator decides `confirmed` or `rejected`, not you.

## Lab

`lab/cloudexplab/app.py` is one loopback server standing in for five third
parties, every fake credential containing `MYTHOS_LAB_CANARY`:

    python3 lab/cloudexplab/app.py --port 5029

    scripts/cloudexp harvest http://127.0.0.1:5029/
    scripts/cloudexp buckets mythos-lab-public mythos-lab-private mythos-lab-missing \
        --provider s3 --endpoint http://127.0.0.1:5029/s3
    scripts/cloudexp buckets mythos-lab-public --provider s3 \
        --endpoint http://127.0.0.1:5029/s3 --key private.txt
    scripts/cloudexp buckets uploads --provider azure \
        --endpoint http://127.0.0.1:5029/azure [--sas 'sv=2022-11-02&sig=…']
    scripts/cloudexp buckets mythos-lab-gcs --provider gcs \
        --endpoint http://127.0.0.1:5029/gcs
    scripts/cloudexp serverless http://127.0.0.1:5029/prod/items \
        --kind api-gateway --stages prod,dev
    scripts/cloudexp orchestrator 127.0.0.1 --endpoint http://127.0.0.1:5029 \
        --only kubelet-readonly,kubelet-readonly-metrics
    scripts/cloudexp clientcreds http://127.0.0.1:5029/static/app.js

`scripts/cloudexp selftest` starts that same fixture on a loopback port and
asserts against it, so the classification tables are checked against the bodies
the providers actually send.
