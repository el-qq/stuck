#!/bin/sh
# Preflight for `npm start` / `npm test`: fail with a clear hint when
# `npm run setup` has not been run yet. POSIX sh, run from the repo root.

ok=0

if [ ! -x backend/.venv/bin/uvicorn ]; then
  echo "error: backend virtualenv is missing (backend/.venv)." >&2
  ok=1
fi

if [ ! -d frontend/node_modules ]; then
  echo "error: frontend dependencies are missing (frontend/node_modules)." >&2
  ok=1
fi

if [ ! -d node_modules/concurrently ]; then
  echo "error: root dependencies are missing (node_modules)." >&2
  ok=1
fi

if [ "$ok" -ne 0 ]; then
  echo "" >&2
  echo "Run \`npm run setup\` first — it prepares the Python venv (backend/)," >&2
  echo "installs frontend and root dependencies, then retry this command." >&2
  exit 1
fi

exit 0
