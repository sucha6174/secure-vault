import { expect } from "chai";
import { ethers } from "hardhat";
import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";
import {
  SecureVault,
  AuthorizationManager,
  MaliciousReentrantRecipient,
  RejectingRecipient,
} from "../typechain-types";

describe("SecureVault", function () {
  let deployer: SignerWithAddress;
  let signer: SignerWithAddress;
  let unauthorizedSigner: SignerWithAddress;
  let depositor1: SignerWithAddress;
  let depositor2: SignerWithAddress;
  let recipient: SignerWithAddress;
  let attacker: SignerWithAddress;
  let authManager: AuthorizationManager;
  let secureVault: SecureVault;
  let chainId: bigint;

  beforeEach(async function () {
    [deployer, signer, unauthorizedSigner, depositor1, depositor2, recipient, attacker] =
      await ethers.getSigners();

    const network = await ethers.provider.getNetwork();
    chainId = network.chainId;

    // Deploy AuthorizationManager
    const AuthManagerFactory = await ethers.getContractFactory("AuthorizationManager");
    authManager = await AuthManagerFactory.deploy();
    await authManager.initialize(signer.address);

    // Deploy SecureVault
    const SecureVaultFactory = await ethers.getContractFactory("SecureVault");
    secureVault = await SecureVaultFactory.deploy();
    await secureVault.initialize(await authManager.getAddress());
  });

  async function generateAuthSignature(
    vaultAddr: string,
    recipientAddr: string,
    amount: bigint,
    nonce: bigint,
    netChainId: bigint = chainId,
    signingAccount: SignerWithAddress = signer
  ) {
    const authHash = await authManager.getAuthHash(
      vaultAddr,
      recipientAddr,
      amount,
      nonce,
      netChainId
    );
    const signature = await signingAccount.signMessage(ethers.getBytes(authHash));
    return { authHash, signature };
  }

  describe("Initialization & Access Control", function () {
    it("should set deployer as the contract owner", async function () {
      expect(await secureVault.owner()).to.equal(deployer.address);
      expect(await secureVault.initialized()).to.equal(true);
      expect(await secureVault.authManager()).to.equal(await authManager.getAddress());
    });

    it("should reject re-initialization", async function () {
      await expect(
        secureVault.connect(deployer).initialize(await authManager.getAddress())
      ).to.be.revertedWith("Already initialized");
    });

    it("should reject initialization by non-owner", async function () {
      const freshVaultFactory = await ethers.getContractFactory("SecureVault");
      const freshVault = await freshVaultFactory.deploy();

      await expect(
        freshVault.connect(attacker).initialize(await authManager.getAddress())
      ).to.be.revertedWithCustomError(freshVault, "OwnableUnauthorizedAccount");
    });

    it("should reject initialization with zero address for auth manager", async function () {
      const freshVaultFactory = await ethers.getContractFactory("SecureVault");
      const freshVault = await freshVaultFactory.deploy();

      await expect(
        freshVault.connect(deployer).initialize(ethers.ZeroAddress)
      ).to.be.revertedWith("Invalid auth manager");
    });

    it("should reject withdrawals if vault is uninitialized", async function () {
      const freshVaultFactory = await ethers.getContractFactory("SecureVault");
      const freshVault = await freshVaultFactory.deploy();

      await expect(
        freshVault.withdraw(recipient.address, ethers.parseEther("1"), 1n, "0x")
      ).to.be.revertedWith("Not initialized");
    });
  });

  describe("Deposits and Accounting", function () {
    it("should accept native ETH via direct transfer (receive()) and emit Deposit event", async function () {
      const depositAmount = ethers.parseEther("2.5");

      await expect(
        depositor1.sendTransaction({
          to: await secureVault.getAddress(),
          value: depositAmount,
        })
      )
        .to.emit(secureVault, "Deposit")
        .withArgs(depositor1.address, depositAmount);

      expect(await secureVault.getBalance()).to.equal(depositAmount);
      expect(await secureVault.totalDeposited()).to.equal(depositAmount);
    });

    it("should accept native ETH via deposit() function and update accounting", async function () {
      const depositAmount = ethers.parseEther("1.0");

      await expect(
        secureVault.connect(depositor2).deposit({ value: depositAmount })
      )
        .to.emit(secureVault, "Deposit")
        .withArgs(depositor2.address, depositAmount);

      expect(await secureVault.getBalance()).to.equal(depositAmount);
      expect(await secureVault.totalDeposited()).to.equal(depositAmount);
    });

    it("should track cumulative deposits across multiple accounts", async function () {
      await depositor1.sendTransaction({
        to: await secureVault.getAddress(),
        value: ethers.parseEther("1.0"),
      });

      await depositor2.sendTransaction({
        to: await secureVault.getAddress(),
        value: ethers.parseEther("2.0"),
      });

      expect(await secureVault.getBalance()).to.equal(ethers.parseEther("3.0"));
      expect(await secureVault.totalDeposited()).to.equal(ethers.parseEther("3.0"));
    });

    it("should reject zero-value deposits", async function () {
      await expect(
        depositor1.sendTransaction({
          to: await secureVault.getAddress(),
          value: 0n,
        })
      ).to.be.revertedWith("Deposit must be greater than zero");

      await expect(
        secureVault.connect(depositor1).deposit({ value: 0n })
      ).to.be.revertedWith("Deposit must be greater than zero");
    });
  });

  describe("Authorized Withdrawals", function () {
    const initialDeposit = ethers.parseEther("5.0");
    const withdrawAmount = ethers.parseEther("1.5");
    const nonce = 5001n;

    beforeEach(async function () {
      await depositor1.sendTransaction({
        to: await secureVault.getAddress(),
        value: initialDeposit,
      });
    });

    it("should execute an authorized withdrawal, update internal accounting, and transfer ETH", async function () {
      const vaultAddress = await secureVault.getAddress();
      const { authHash, signature } = await generateAuthSignature(
        vaultAddress,
        recipient.address,
        withdrawAmount,
        nonce
      );

      const recipientBalBefore = await ethers.provider.getBalance(recipient.address);
      const vaultBalBefore = await secureVault.getBalance();
      const totalWithdrawnBefore = await secureVault.totalWithdrawn();

      const tx = await secureVault.withdraw(recipient.address, withdrawAmount, nonce, signature);

      // Verify events on both contracts
      await expect(tx)
        .to.emit(secureVault, "Withdrawal")
        .withArgs(recipient.address, withdrawAmount);

      await expect(tx)
        .to.emit(authManager, "AuthorizationConsumed")
        .withArgs(authHash);

      // Verify accounting: totalWithdrawn incremented exactly once
      expect(await secureVault.totalWithdrawn()).to.equal(totalWithdrawnBefore + withdrawAmount);

      // Verify vault balance decreased
      expect(await secureVault.getBalance()).to.equal(vaultBalBefore - withdrawAmount);

      // Verify recipient received exact amount
      const recipientBalAfter = await ethers.provider.getBalance(recipient.address);
      expect(recipientBalAfter - recipientBalBefore).to.equal(withdrawAmount);

      // Verify authorization is consumed on AuthorizationManager
      expect(await authManager.usedAuthorizations(authHash)).to.equal(true);
    });

    it("should reject withdrawal if vault balance is insufficient", async function () {
      const excessiveAmount = ethers.parseEther("10.0"); // Vault only has 5 ETH
      const vaultAddress = await secureVault.getAddress();
      const { signature } = await generateAuthSignature(
        vaultAddress,
        recipient.address,
        excessiveAmount,
        nonce
      );

      await expect(
        secureVault.withdraw(recipient.address, excessiveAmount, nonce, signature)
      ).to.be.revertedWith("Insufficient balance");
    });

    it("should reject zero recipient address", async function () {
      const vaultAddress = await secureVault.getAddress();
      const { signature } = await generateAuthSignature(
        vaultAddress,
        ethers.ZeroAddress,
        withdrawAmount,
        nonce
      );

      await expect(
        secureVault.withdraw(ethers.ZeroAddress, withdrawAmount, nonce, signature)
      ).to.be.revertedWith("Invalid recipient");
    });

    it("should reject zero withdrawal amount", async function () {
      const vaultAddress = await secureVault.getAddress();
      const { signature } = await generateAuthSignature(
        vaultAddress,
        recipient.address,
        0n,
        nonce
      );

      await expect(
        secureVault.withdraw(recipient.address, 0n, nonce, signature)
      ).to.be.revertedWith("Invalid amount");
    });

    it("should reject withdrawal with signature from unauthorized signer", async function () {
      const vaultAddress = await secureVault.getAddress();
      const { signature } = await generateAuthSignature(
        vaultAddress,
        recipient.address,
        withdrawAmount,
        nonce,
        chainId,
        unauthorizedSigner
      );

      await expect(
        secureVault.withdraw(recipient.address, withdrawAmount, nonce, signature)
      ).to.be.revertedWith("Invalid signature");
    });

    it("should reject withdrawal when recipient is modified", async function () {
      const vaultAddress = await secureVault.getAddress();
      const { signature } = await generateAuthSignature(
        vaultAddress,
        recipient.address,
        withdrawAmount,
        nonce
      );

      // Submit with attacker's address instead of recipient
      await expect(
        secureVault.withdraw(attacker.address, withdrawAmount, nonce, signature)
      ).to.be.revertedWith("Invalid signature");
    });

    it("should reject withdrawal when amount is modified", async function () {
      const vaultAddress = await secureVault.getAddress();
      const { signature } = await generateAuthSignature(
        vaultAddress,
        recipient.address,
        withdrawAmount,
        nonce
      );

      // Submit with different amount
      await expect(
        secureVault.withdraw(recipient.address, withdrawAmount + 1n, nonce, signature)
      ).to.be.revertedWith("Invalid signature");
    });

    it("should reject withdrawal when nonce is modified", async function () {
      const vaultAddress = await secureVault.getAddress();
      const { signature } = await generateAuthSignature(
        vaultAddress,
        recipient.address,
        withdrawAmount,
        nonce
      );

      // Submit with different nonce
      await expect(
        secureVault.withdraw(recipient.address, withdrawAmount, nonce + 1n, signature)
      ).to.be.revertedWith("Invalid signature");
    });
  });

  describe("Replay Protection, Atomicity & Adversarial Scenarios", function () {
    const initialDeposit = ethers.parseEther("5.0");
    const withdrawAmount = ethers.parseEther("2.0");
    const nonce = 777n;

    beforeEach(async function () {
      await depositor1.sendTransaction({
        to: await secureVault.getAddress(),
        value: initialDeposit,
      });
    });

    it("should prevent replay attacks: consuming the same authorization a second time must revert", async function () {
      const vaultAddress = await secureVault.getAddress();
      const { signature } = await generateAuthSignature(
        vaultAddress,
        recipient.address,
        withdrawAmount,
        nonce
      );

      // First withdrawal succeeds
      await secureVault.withdraw(recipient.address, withdrawAmount, nonce, signature);
      expect(await secureVault.totalWithdrawn()).to.equal(withdrawAmount);

      const vaultBalanceAfterFirst = await secureVault.getBalance();

      // Second withdrawal attempt with exact same params must revert deterministically
      await expect(
        secureVault.withdraw(recipient.address, withdrawAmount, nonce, signature)
      ).to.be.revertedWith("Authorization already used");

      // Invariant: Balance and totalWithdrawn must NOT be affected by the failed replay attempt
      expect(await secureVault.getBalance()).to.equal(vaultBalanceAfterFirst);
      expect(await secureVault.totalWithdrawn()).to.equal(withdrawAmount);
    });

    it("should preserve atomicity: failed ETH transfer reverts authorization consumption and accounting", async function () {
      const RejectingFactory = await ethers.getContractFactory("RejectingRecipient");
      const rejectingRecipient = await RejectingFactory.deploy();
      const rejectingAddr = await rejectingRecipient.getAddress();

      const vaultAddress = await secureVault.getAddress();
      const { authHash, signature } = await generateAuthSignature(
        vaultAddress,
        rejectingAddr,
        withdrawAmount,
        nonce
      );

      const vaultBalanceBefore = await secureVault.getBalance();
      const totalWithdrawnBefore = await secureVault.totalWithdrawn();

      // Recipient rejects ETH transfer -> whole transaction must revert
      await expect(
        secureVault.withdraw(rejectingAddr, withdrawAmount, nonce, signature)
      ).to.be.revertedWith("Transfer failed");

      // Critical Invariant: Atomicity ensures state is completely rolled back
      expect(await secureVault.getBalance()).to.equal(vaultBalanceBefore);
      expect(await secureVault.totalWithdrawn()).to.equal(totalWithdrawnBefore);
      // Authorization must NOT be marked consumed because transaction reverted
      expect(await authManager.usedAuthorizations(authHash)).to.equal(false);
    });

    it("should prevent reentrancy attacks: reentrant call into withdraw must fail", async function () {
      const vaultAddress = await secureVault.getAddress();
      const AttackerFactory = await ethers.getContractFactory("MaliciousReentrantRecipient");
      const reentrantAttacker = await AttackerFactory.deploy(vaultAddress);
      const attackerContractAddr = await reentrantAttacker.getAddress();

      const { signature } = await generateAuthSignature(
        vaultAddress,
        attackerContractAddr,
        withdrawAmount,
        nonce
      );

      // Configure attacker to attempt reentrant call with same credentials
      await reentrantAttacker.setAttackParams(withdrawAmount, nonce, signature);

      const vaultBalBefore = await secureVault.getBalance();
      const totalWithdrawnBefore = await secureVault.totalWithdrawn();

      // Withdrawal must revert when reentrancy is attempted
      await expect(
        secureVault.withdraw(attackerContractAddr, withdrawAmount, nonce, signature)
      ).to.be.reverted;

      // Invariant: Vault assets are completely protected
      expect(await secureVault.getBalance()).to.equal(vaultBalBefore);
      expect(await secureVault.totalWithdrawn()).to.equal(totalWithdrawnBefore);
    });
  });
});
