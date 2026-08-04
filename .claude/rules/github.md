# GitHub Repository Platform — ABSOLUTE RULES

This repository is hosted on **GitHub**. You MUST use the `gh` CLI for all PR and issue operations.

---

## Branch Naming Convention

All branches MUST follow this format, where `<type>` is a commit type (`feat`, `fix`, `refactor`, `test`, `docs`, `chore`, `style`):

```
<type>/<description-with-dashes>
```

If the branch implements a plan from `docs/plans/`, it MUST follow this format instead, where `<plan-number>` is the plan's ID:

```
<type>/plan-<plan-number>-<description-with-dashes>
```

**Examples**: `feat/s3-storage-layer`, `fix/state-file-atomic-write`, `feat/plan-1-initial-implementation`

## Pull Requests

Create PRs via `gh pr create`:

```bash
gh pr create \
  --base main \
  --head "<type>/<description>" \
  --title "<type>: <short description>" \
  --body "$(cat <<'EOF'
## Summary
- <bullet points describing the changes>
EOF
)"
```

**IMPORTANT**: After creating a PR, you MUST ALWAYS report the full PR URL back to the user.
