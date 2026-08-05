#!/usr/bin/env bash
# Validate every Mermaid block in every *.md under a directory (default: docs).
set -uo pipefail

DIR="${1:-docs}"
# Load nvm if present (so npx/node are on PATH); ignore if unavailable.
[ -n "${NVM_DIR:-}" ] && [ -s "$NVM_DIR/nvm.sh" ] && . "$NVM_DIR/nvm.sh"

fail=0
while IFS= read -r -d '' md; do
  if ! python3 - "$md" <<'PY'
import re, subprocess, sys, json, tempfile, os
puppet = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)
json.dump({'args': ['--no-sandbox']}, puppet)
puppet.close()
content = open(sys.argv[1]).read()
blocks = re.findall(r'```mermaid\n(.*?)\n```', content, re.DOTALL)
bad = False
for i, block in enumerate(blocks):
    mmd = f'/tmp/mmc_{os.getpid()}_{i}.mmd'
    with open(mmd, 'w') as f:
        f.write(block)
    r = subprocess.run(
        ['npx', '--yes', '@mermaid-js/mermaid-cli', '-p', puppet.name,
         '-i', mmd, '-o', f'/tmp/mmc_{os.getpid()}_{i}.svg'],
        capture_output=True, text=True, timeout=120)
    if r.returncode != 0:
        bad = True
        sys.stderr.write(f'{sys.argv[1]} chart {i}: FAILED\n{r.stderr[:500]}\n')
os.unlink(puppet.name)
sys.exit(1 if bad else 0)
PY
  then
    fail=1
  fi
done < <(find "$DIR" -name '*.md' -print0)

exit "$fail"
