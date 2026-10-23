import { ethers } from "hardhat";
import * as fs from "fs";
import * as path from "path";

async function main() {
  console.log("==================================================================");
  console.log("         SECURE VAULT SYSTEM - AUTOMATIC DEPLOYMENT               ");
  console.log("==================================================================");

  const [deployer, defaultSigner] = await ethers.getSigners();
  const network = await ethers.provider.getNetwork();

  console.log(`[INFO] Network Name:  ${network.name}`);
  console.log(`[INFO] Network ID / Chain ID: ${network.chainId.toString()}`);
  console.log(`[INFO] Deployer Address: ${deployer.address}`);

  const deployerBalance = await ethers.provider.getBalance(deployer.address);
  console.log(`[INFO] Deployer Balance: ${ethers.formatEther(deployerBalance)} ETH`);

  // Signer resolution: use SIGNER_ADDRESS env if provided, else use second hardhat signer
  const devSignerAddress = process.env.SIGNER_ADDRESS || (defaultSigner ? defaultSigner.address : deployer.address);
  console.log(`[INFO] Trusted Signer: ${devSignerAddress}`);

  // Step 1: Deploy AuthorizationManager
  console.log("\n[DEPLOY] Deploying AuthorizationManager...");
  const AuthManagerFactory = await ethers.getContractFactory("AuthorizationManager", deployer);
  const authManager = await AuthManagerFactory.deploy();
  await authManager.waitForDeployment();
  const authManagerAddress = await authManager.getAddress();
  console.log(`[SUCCESS] AuthorizationManager deployed to: ${authManagerAddress}`);

  // Step 2: Initialize AuthorizationManager with trusted signer (protected by onlyOwner)
  console.log(`[INIT] Initializing AuthorizationManager with signer ${devSignerAddress}...`);
  const initAuthTx = await authManager.initialize(devSignerAddress);
  await initAuthTx.wait();
  console.log(`[SUCCESS] AuthorizationManager initialized.`);

  // Step 3: Deploy SecureVault
  console.log("\n[DEPLOY] Deploying SecureVault...");
  const SecureVaultFactory = await ethers.getContractFactory("SecureVault", deployer);
  const secureVault = await SecureVaultFactory.deploy();
  await secureVault.waitForDeployment();
  const secureVaultAddress = await secureVault.getAddress();
  console.log(`[SUCCESS] SecureVault deployed to: ${secureVaultAddress}`);

  // Step 4: Initialize SecureVault with AuthorizationManager address (protected by onlyOwner)
  console.log(`[INIT] Initializing SecureVault with AuthManager ${authManagerAddress}...`);
  const initVaultTx = await secureVault.initialize(authManagerAddress);
  await initVaultTx.wait();
  console.log(`[SUCCESS] SecureVault initialized.`);

  // Step 5: Save deployment metadata to deployment-info.json
  const deploymentInfo = {
    network: network.name,
    chainId: network.chainId.toString(),
    deployer: deployer.address,
    trustedSigner: devSignerAddress,
    contracts: {
      AuthorizationManager: authManagerAddress,
      SecureVault: secureVaultAddress,
    },
    deployedAt: new Date().toISOString(),
  };

  const outputPath = path.join(__dirname, "..", "deployment-info.json");
  fs.writeFileSync(outputPath, JSON.stringify(deploymentInfo, null, 2));
  console.log(`\n[INFO] Deployment details saved to: ${outputPath}`);

  console.log("\n==================================================================");
  console.log("                   DEPLOYMENT COMPLETE                            ");
  console.log("==================================================================");
  console.log(`Network Chain ID:         ${network.chainId.toString()}`);
  console.log(`AuthorizationManager:     ${authManagerAddress}`);
  console.log(`SecureVault:              ${secureVaultAddress}`);
  console.log(`Trusted Signer Address:   ${devSignerAddress}`);
  console.log("==================================================================\n");
}

main().catch((error) => {
  console.error("[FATAL] Deployment failed:", error);
  process.exitCode = 1;
});
