# Patch Diffing — reading the root cause out of the vendor fix

**Class:** methodology  **Updated:** 2026-10-25

## What it is
Real red teamers read the patch, not the advisory prose, to find the root cause
and thereby the shortest path to a minimal PoC. The diff shows: which function
was missing its validation, which new sanitizer was added, which line now calls
a normalize helper.

## Workflow

1. **Advisory → version.** Map the exact affected versions from the advisory
   onto the repository history.
2. **Fetch the diff.** For open source: `git diff <vuln-tag> <fixed-tag> --
   <path>` or the GitHub commit link from the NVD references. For closed
   source: binary diffing (BinDiff etc.) — usually unnecessary for lab targets.
3. **Three questions for every diff:**
   - *Where* was the missing control? (File/function = best starting point for
     mapping the PoC request: which HTTP route reaches that code?)
   - *Which input* now flows into the new sanitizer? (A parameter name in the
     diff = the parameter name in the request.)
   - *Does this overlap an earlier CVE?* (Patch bypass, e.g. SharePoint:
     CVE-2025-53771 is a patch bypass for CVE-2025-49706 — an important class!)
4. **To PoC:** framework route from the diff → URL pattern + parameter →
   minimal proof of concept in the lab.
5. **To detection:** the diff shows where the flaw sits logically — this is
   what turns into Mythos parameter heuristics (fuzz lists, request features).

## Non-destructive confirmation

Always reproduce on both the vulnerable and the fixed version in the lab: the
proof must trigger on the vulnerable build and not on the patched one. That is
exactly Mythos' "confirmed" vs "tentative" distinction (the deterministic PoC
replay requirement from the ROADMAP).

## Sources

- PortSwigger-style patch-diff research write-ups (2025-2026)
- CISA KEV SharePoint entry CVE-2026-20963 — patch-bypass chain (2026-04)
