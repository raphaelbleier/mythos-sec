## What this changes

<!-- One or two sentences. If it fixes an issue, say "Fixes #123". -->

## Why

<!-- What was wrong or missing. If the reason is not obvious from the diff, it belongs here. -->

## How it was verified

```
bash scripts/selftest.sh
```

<!-- Paste the last line, or say which checks you ran. If the change touches
     cli/, add `npm run check --prefix cli`. If it touches toolbox/, add
     `scripts/selftest.sh --with-docker`. -->

## Checks

- [ ] `bash scripts/selftest.sh` passes.
- [ ] A new or changed script in `scripts/` has a `--selftest`, and a new guard rule has its assertion plus the negative case.
- [ ] A new skill has valid YAML frontmatter, a `name` matching its directory, and an entry in `skills/registry.yaml`.
- [ ] Any new capability was exercised against a deliberately vulnerable target in `lab/`, never against a third-party host. Which one: <!-- e.g. lab/authlab, http://127.0.0.1:5023 -->
- [ ] The diff contains no real target hostname, no engagement artifact, no scope file and no credential. Fake credentials in `lab/` are the canary string `MYTHOS_LAB_CANARY`.
- [ ] The change does not widen, weaken or bypass the scope guard, and adds no destruction, brute-force or denial-of-service capability.
- [ ] Commit messages follow Conventional Commits (`feat`, `fix`, `docs`, `chore`), and carry no AI attribution.
