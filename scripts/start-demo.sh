#!/usr/bin/env bash
# One command demo: local blockchain + deploy contract + web app/storage on http://localhost:3000
set -e
cd "$(dirname "$0")/.."
npx hardhat node > /tmp/securevault-node.log 2>&1 &
NODE_PID=$!; trap "kill $NODE_PID 2>/dev/null" EXIT
sleep 6
npx hardhat run scripts/deploy.js --network localhost
node server/server.js
