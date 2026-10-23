#!/bin/sh
set -e

echo "=================================================================="
echo "           STARTING SECURE VAULT DEPLOYER CONTAINER               "
echo "=================================================================="

RPC_TARGET="${RPC_URL:-http://blockchain:8545}"
echo "[WAIT] Waiting for blockchain RPC at ${RPC_TARGET} to become ready..."

MAX_RETRIES=30
COUNT=0

until node -e "fetch('${RPC_TARGET}', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({jsonrpc:'2.0',method:'eth_blockNumber',params:[],id:1})}).then(r=>r.ok?process.exit(0):process.exit(1)).catch(()=>process.exit(1))" 2>/dev/null; do
  COUNT=$((COUNT+1))
  if [ $COUNT -ge $MAX_RETRIES ]; then
    echo "[ERROR] Timed out waiting for RPC node at ${RPC_TARGET}."
    exit 1
  fi
  echo "[WAIT] Node not ready yet... retry ${COUNT}/${MAX_RETRIES}"
  sleep 2
done

echo "[READY] Blockchain node is ready!"
echo ""
echo "[BUILD] Compiling smart contracts..."
npx hardhat compile

echo ""
echo "[DEPLOY] Executing deployment script..."
npx hardhat run scripts/deploy.ts --network localhost

echo ""
echo "[INFO] Copying deployment info to output volume if mounted..."
if [ -d "/output" ]; then
  cp -f deployment-info.json /output/deployment-info.json 2>/dev/null || true
  echo "[INFO] Copied deployment-info.json to /output/"
fi

echo ""
echo "=================================================================="
echo "       SECURE VAULT DEPLOYMENT COMPLETED SUCCESSFULLY             "
echo "=================================================================="

# Keep container alive to allow inspection or docker compose logs
tail -f /dev/null
