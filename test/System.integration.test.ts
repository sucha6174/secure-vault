import { expect } from "chai";
import { ethers } from "hardhat";
import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";
import { SecureVault, AuthorizationManager } from "../typechain-types";

describe("System Integration & Invariant Tests", function () {
  let deployer: SignerWithAddress;
  let trustedSigner: SignerWithAddress;
  let alice: SignerWithAddress;
  let bob: SignerWithAddress;
  let charlie: SignerWithAddress;
  let eve: SignerWithAddress;

  let authManager: AuthorizationManager;
  let vaultA: SecureVault;
  let vaultB: SecureVault;
  let chainId: bigint;

  beforeEach(async function () {
    [deployer, trustedSigner, alice, bob, charlie, eve] = await ethers.getSigners();

    const net = await ethers.provider.getNetwork();
    chainId = net.chainId;

    // 1. Deploy AuthorizationManager
    const AuthManagerFactory = await ethers.getContractFactory("AuthorizationManager");
    authManager = await AuthManagerFactory.deploy();
    await authManager.initialize(trustedSigner.address);

    // 2. Deploy Vault A
    const SecureVaultFactory = await ethers.getContractFactory("SecureVault");
    vaultA = await SecureVaultFactory.deploy();
    await vaultA.initialize(await authManager.getAddress());

    // 3. Deploy Vault B (to test multi-vault isolation)
    vaultB = await SecureVaultFactory.deploy();
    await vaultB.initialize(await authManager.getAddress());
  });

  async function createAuthorization(
    vault: SecureVault,
    recipient: string,
    amount: bigint,
    nonce: bigint,
    customChainId: bigint = chainId,
    signer: SignerWithAddress = trustedSigner
  ) {
    const vaultAddress = await vault.getAddress();
    const authHash = await authManager.getAuthHash(
      vaultAddress,
      recipient,
      amount,
      nonce,
      customChainId
    );
    const signature = await signer.signMessage(ethers.getBytes(authHash));
    return { authHash, signature, vaultAddress };
  }

  describe("Multi-Actor Deposit & Withdrawal Lifecycle", function () {
    it("should handle interleaved deposits, withdrawals, and maintain exact accounting invariants", async function () {
      // Alice deposits 10 ETH
      await alice.sendTransaction({
        to: await vaultA.getAddress(),
        value: ethers.parseEther("10"),
      });

      // Bob deposits 5 ETH
      await bob.sendTransaction({
        to: await vaultA.getAddress(),
        value: ethers.parseEther("5"),
      });

      expect(await vaultA.getBalance()).to.equal(ethers.parseEther("15"));
      expect(await vaultA.totalDeposited()).to.equal(ethers.parseEther("15"));
      expect(await vaultA.totalWithdrawn()).to.equal(0n);

      // Withdrawal 1: Charlie withdraws 3 ETH (nonce: 100)
      const auth1 = await createAuthorization(vaultA, charlie.address, ethers.parseEther("3"), 100n);
      await vaultA.withdraw(charlie.address, ethers.parseEther("3"), 100n, auth1.signature);

      // Withdrawal 2: Bob withdraws 4 ETH (nonce: 250 - non-sequential)
      const auth2 = await createAuthorization(vaultA, bob.address, ethers.parseEther("4"), 250n);
      await vaultA.withdraw(bob.address, ethers.parseEther("4"), 250n, auth2.signature);

      // Alice deposits another 2 ETH
      await alice.sendTransaction({
        to: await vaultA.getAddress(),
        value: ethers.parseEther("2"),
      });

      // Withdrawal 3: Alice withdraws 1 ETH (nonce: 300)
      const auth3 = await createAuthorization(vaultA, alice.address, ethers.parseEther("1"), 300n);
      await vaultA.withdraw(alice.address, ethers.parseEther("1"), 300n, auth3.signature);

      // Verify System Invariants
      const expectedDeposited = ethers.parseEther("17"); // 10 + 5 + 2
      const expectedWithdrawn = ethers.parseEther("8");  // 3 + 4 + 1
      const expectedBalance = expectedDeposited - expectedWithdrawn; // 9 ETH

      expect(await vaultA.totalDeposited()).to.equal(expectedDeposited);
      expect(await vaultA.totalWithdrawn()).to.equal(expectedWithdrawn);
      expect(await vaultA.getBalance()).to.equal(expectedBalance);

      // INVARIANT: Balance must equal totalDeposited - totalWithdrawn
      expect(await vaultA.getBalance()).to.equal(
        (await vaultA.totalDeposited()) - (await vaultA.totalWithdrawn())
      );

      // INVARIANT: All three authorizations are consumed
      expect(await authManager.usedAuthorizations(auth1.authHash)).to.equal(true);
      expect(await authManager.usedAuthorizations(auth2.authHash)).to.equal(true);
      expect(await authManager.usedAuthorizations(auth3.authHash)).to.equal(true);
    });
  });

  describe("Cross-Vault and Cross-Chain Isolation Invariants", function () {
    it("should prevent cross-vault replay: authorization for Vault A cannot be executed on Vault B", async function () {
      // Deposit funds to both vaults
      await alice.sendTransaction({
        to: await vaultA.getAddress(),
        value: ethers.parseEther("5"),
      });
      await alice.sendTransaction({
        to: await vaultB.getAddress(),
        value: ethers.parseEther("5"),
      });

      const withdrawalAmount = ethers.parseEther("1.0");
      const nonce = 888n;

      // Create authorization bound to Vault A
      const authForVaultA = await createAuthorization(
        vaultA,
        charlie.address,
        withdrawalAmount,
        nonce
      );

      // Attempt to execute this authorization on Vault B
      // Vault B's withdraw passes address(this) [Vault B], causing hash mismatch in AuthorizationManager
      await expect(
        vaultB.withdraw(charlie.address, withdrawalAmount, nonce, authForVaultA.signature)
      ).to.be.revertedWith("Invalid signature");

      // Verify Vault A can execute its legitimate authorization
      await expect(
        vaultA.withdraw(charlie.address, withdrawalAmount, nonce, authForVaultA.signature)
      )
        .to.emit(vaultA, "Withdrawal")
        .withArgs(charlie.address, withdrawalAmount);
    });

    it("should prevent cross-chain replay: authorization signed for a different chain ID is rejected", async function () {
      await alice.sendTransaction({
        to: await vaultA.getAddress(),
        value: ethers.parseEther("5"),
      });

      const withdrawalAmount = ethers.parseEther("1.0");
      const nonce = 999n;
      const ethereumMainnetChainId = 1n;

      const crossChainAuth = await createAuthorization(
        vaultA,
        charlie.address,
        withdrawalAmount,
        nonce,
        ethereumMainnetChainId
      );

      await expect(
        vaultA.withdraw(charlie.address, withdrawalAmount, nonce, crossChainAuth.signature)
      ).to.be.revertedWith("Invalid signature");
    });

    it("should prevent direct consumption: external attacker cannot call verifyAuthorization directly", async function () {
      const withdrawalAmount = ethers.parseEther("1.0");
      const nonce = 555n;

      const auth = await createAuthorization(
        vaultA,
        charlie.address,
        withdrawalAmount,
        nonce
      );

      // Eve attempts to call AuthorizationManager directly to grief Charlie's authorization
      await expect(
        authManager
          .connect(eve)
          .verifyAuthorization(
            await vaultA.getAddress(),
            charlie.address,
            withdrawalAmount,
            nonce,
            auth.signature
          )
      ).to.be.revertedWith("Caller must be vault");

      // Charlie's authorization remains completely unconsumed and valid
      expect(await authManager.usedAuthorizations(auth.authHash)).to.equal(false);

      // Vault A can still execute the withdrawal normally
      await alice.sendTransaction({
        to: await vaultA.getAddress(),
        value: ethers.parseEther("2"),
      });
      await expect(
        vaultA.withdraw(charlie.address, withdrawalAmount, nonce, auth.signature)
      ).to.emit(vaultA, "Withdrawal");
    });
  });
});
