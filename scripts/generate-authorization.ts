import { ethers } from "hardhat";
import * as fs from "fs";
import * as path from "path";

async function main() {
  console.log("==================================================================");
  console.log("     OFF-CHAIN WITHDRAWAL AUTHORIZATION GENERATOR                ");
  console.log("==================================================================");

  const deploymentPath = path.join(__dirname, "..", "deployment-info.json");
  let vaultAddress: string | undefined;
  let authManagerAddress: string | undefined;

  if (fs.existsSync(deploymentPath)) {
    const deploymentData = JSON.parse(fs.readFileSync(deploymentPath, "utf-8"));
    vaultAddress = deploymentData.contracts?.SecureVault;
    authManagerAddress = deploymentData.contracts?.AuthorizationManager;
  }

  // Fallback defaults for demonstration / testing
  const [deployer, defaultSigner, defaultRecipient] = await ethers.getSigners();
  vaultAddress = process.env.VAULT_ADDRESS || vaultAddress || deployer.address;
  const recipientAddress = process.env.RECIPIENT_ADDRESS || defaultRecipient.address;
  const amountWei = process.env.AMOUNT_WEI
    ? BigInt(process.env.AMOUNT_WEI)
    : ethers.parseEther("0.5");
  const nonce = process.env.NONCE ? BigInt(process.env.NONCE) : BigInt(Date.now());

  const network = await ethers.provider.getNetwork();
  const chainId = network.chainId;

  // Signer key: default to local development signer account (#1)
  const signerAccount = defaultSigner || deployer;

  console.log(`[PARAMS] Vault Address:      ${vaultAddress}`);
  console.log(`[PARAMS] Recipient Address:  ${recipientAddress}`);
  console.log(`[PARAMS] Amount (wei):       ${amountWei.toString()} (${ethers.formatEther(amountWei)} ETH)`);
  console.log(`[PARAMS] Nonce:              ${nonce.toString()}`);
  console.log(`[PARAMS] Chain ID:           ${chainId.toString()}`);
  console.log(`[PARAMS] Trusted Signer:     ${signerAccount.address}`);

  // Compute deterministic hash: keccak256(abi.encodePacked(vault, recipient, amount, nonce, chainId))
  const authHash = ethers.solidityPackedKeccak256(
    ["address", "address", "uint256", "uint256", "uint256"],
    [vaultAddress, recipientAddress, amountWei, nonce, chainId]
  );
  console.log(`\n[HASH] Authorization Hash:  ${authHash}`);

  // Sign the Ethereum Signed Message hash: \x19Ethereum Signed Message:\n32 + authHash
  const signature = await signerAccount.signMessage(ethers.getBytes(authHash));
  console.log(`[SIG]  ECDSA Signature:       ${signature}`);

  console.log("\n==================================================================");
  console.log("To execute this withdrawal on-chain via SecureVault.withdraw():");
  console.log(`  recipient: "${recipientAddress}"`);
  console.log(`  amount:    ${amountWei.toString()} /* ${ethers.formatEther(amountWei)} ETH */`);
  console.log(`  nonce:     ${nonce.toString()}`);
  console.log(`  signature: "${signature}"`);
  console.log("==================================================================\n");
}

main().catch((error) => {
  console.error("[ERROR] Failed to generate authorization:", error);
  process.exitCode = 1;
});
