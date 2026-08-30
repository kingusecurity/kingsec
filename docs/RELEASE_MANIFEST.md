# `release_manifest.json` Reference

`release_manifest.json` (repository root) is a hand-maintained, informational
snapshot of the current release's identity and headline characteristics — it
is not consumed by any build, packaging, or runtime code path. No CI job,
the Dockerfile, `pyproject.toml`, or the application itself reads this file;
it exists purely for humans (and any future tooling) inspecting the
repository to answer "what release is this."

## Field: `git.commit`

```json
"git": {
  "commit": "<commit-hash>",
  "branch": "main",
  "dirty": false
}
```

**Accepted semantics:** `git.commit` identifies the source commit from
which the release metadata in this file was generated — the commit that
was `HEAD` at the moment an engineer last updated this file — not
necessarily the commit that contains the manifest file itself.

**Why this is unavoidable, not a bug:** a Git commit's hash is computed
from its own tree contents, and this file is part of that tree. A commit
therefore cannot contain its own resulting hash inside itself — the hash
does not exist yet at the moment the file's content is finalized. Any
commit that touches this file will, by construction, record the *previous*
commit's hash (its own parent) as the most recent value that could exist
at authoring time.

**Consequence:** it is normal and expected for `git.commit` to differ from
the actual current `HEAD` by however many commits have landed since this
file was last updated — including the commit that updated the file itself,
and any commits made afterward that didn't touch it again. This does **not**
mean the field is stale, broken, or was written incorrectly.

**What NOT to do:** do not "fix" this field by regenerating it to equal the
current `HEAD` outside of an intentional, reviewed update to the manifest
as a whole (i.e., don't create a commit whose only purpose is chasing this
field into agreement with itself — that commit would immediately be one
commit ahead of its own recorded value again). Update this field only as
part of a deliberate release-metadata refresh, and expect it to name that
refresh commit's parent, not itself.

## Other fields

- `version`, `codename`, `build.*`, `frontend.*`: authoritative version
  identifiers — should match `pyproject.toml`, `src/kingsec/__init__.py`,
  and `frontend/package.json` at the time of each update.
- `database.*`, `api.*`, `modules.*` (e.g. `endpoints_count`,
  `tables_count`, `python_total`): hand-maintained, point-in-time counts.
  These are informational estimates, not verified programmatically, and
  will drift as the codebase changes between manifest updates. Treat them
  as approximate, not authoritative, unless independently re-counted.
- `security.*`, `features`, `supported_platforms`, `supported_python`:
  descriptive summaries of the release's capabilities and support matrix.

None of the fields in this file are read by the application at runtime,
by the Docker build, or by any CI/CD workflow. Its sole purpose is a
human-readable release fingerprint.
