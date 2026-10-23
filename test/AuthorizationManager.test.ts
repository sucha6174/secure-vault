import { expect } from "chai";
import { ethers } from "hardhat";
import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";
import { AuthorizationManager } from "../typechain-types";

describe("AuthorizationManager", function () {
  let deployer: SignerWithAddress;
  let signer: SignerWithAddress;
  let unauthorizedSigner: SignerWithAddress;
  let recipient: SignerWithAddress;
  let otherAccount: SignerWithAddress;
  let mockVault: SignerWithAddress;
  let authManager: AuthorizationManager;
  let chainId: bigint;

  beforeEach(async function () {
    [deployer, signer, unauthorizedSigner, recipient, otherAccount, mockVault] =
      await ethers.getSigners();

    const network = await ethers.provider.getNetwork();
    chainId = network.chainId;

    const AuthManagerFactory = await ethers.getContractFactory("AuthorizationManager");
    authManager = await AuthManagerFactory.deploy();
  });

  describe("Initialization & Access Control", function () {
    it("should set deployer as the initial owner", async function () {
      expect(await authManager.owner()).to.equal(deployer.address);
      expect(await authManager.initialized()).to.equal(false);
    });

    it("should allow owner to initialize with a valid signer", async function () {
      await expect(authManager.connect(deployer).initialize(signer.address)).to.not.be.reverted;
      expect(await authManager.signer()).to.equal(signer.address);
      expect(await authManager.initialized()).to.equal(true);
    });

    it("should reject initialization by non-owner", async function () {
      await expect(
        authManager.connect(otherAccount).initialize(signer.address)
      ).to.be.revertedWithCustomError(authManager, "OwnableUnauthorizedAccount");
    });

    it("should reject initialization with zero address", async function () {
      await expect(
        authManager.connect(deployer).initialize(ethers.ZeroAddress)
      ).to.be.revertedWith("Invalid signer address");
    });

    it("should prevent double initialization", async function () {
      await authManager.connect(deployer).initialize(signer.address);
      await expect(
        authManager.connect(deployer).initialize(signer.address)
      ).to.be.revertedWith("Already initialized");
    });

    it("should allow owner to rotate signer", async function () {
      await authManager.connect(deployer).initialize(signer.address);
      await expect(authManager.connect(deployer).setSigner(otherAccount.address)).to.not.be.reverted;
      expect(await authManager.signer()).to.equal(otherAccount.address);
    });

    it("should reject signer rotation with zero address", async function () {
      await authManager.connect(deployer).initialize(signer.address);
      await expect(
        authManager.connect(deployer).setSigner(ethers.ZeroAddress)
      ).to.be.revertedWith("Invalid signer address");
    });

    it("should reject signer rotation by non-owner", async function () {
      await authManager.connect(deployer).initialize(signer.address);
      await expect(
        authManager.connect(otherAccount).setSigner(otherAccount.address)
      ).to.be.revertedWithCustomError(authManager, "OwnableUnauthorizedAccount");
    });
  });

  describe("Authorization Verification & Replay Protection", function () {
    const amount = ethers.parseEther("1.5");
    const nonce = 1001n;

    beforeEach(async function () {
      await authManager.connect(deployer).initialize(signer.address);
    });

    async function generateSignature(
      vaultAddr: string,
      recipientAddr: string,
      withdrawalAmount: bigint,
      withdrawalNonce: bigint,
      signingChainId: bigint,
      signingAccount: SignerWithAddress = signer
    ) {
      const authHash = await authManager.getAuthHash(
        vaultAddr,
        recipientAddr,
        withdrawalAmount,
        withdrawalNonce,
        signingChainId
      );
      const signature = await signingAccount.signMessage(ethers.getBytes(authHash));
      return { authHash, signature };
    }

    it("should compute deterministic auth hash matching Solidity and Ethers", async function () {
      const onChainHash = await authManager.getAuthHash(
        mockVault.address,
        recipient.address,
        amount,
        nonce,
        chainId
      );
      const offChainHash = ethers.solidityPackedKeccak256(
        ["address", "address", "uint256", "uint256", "uint256"],
        [mockVault.address, recipient.address, amount, nonce, chainId]
      );
      expect(onChainHash).to.equal(offChainHash);
    });

    it("should reject verification if contract is not initialized", async function () {
      const uninitFactory = await ethers.getContractFactory("AuthorizationManager");
      const uninitMgr = await uninitFactory.deploy();
      const { signature } = await generateSignature(
        mockVault.address,
        recipient.address,
        amount,
        nonce,
        chainId
      );

      await expect(
        uninitMgr
          .connect(mockVault)
          .verifyAuthorization(mockVault.address, recipient.address, amount, nonce, signature)
      ).to.be.revertedWith("Not initialized");
    });

    it("should reject verification if caller is not the designated vault (prevents front-running/griefing)", async function () {
      const { signature } = await generateSignature(
        mockVault.address,
        recipient.address,
        amount,
        nonce,
        chainId
      );

      // Caller is otherAccount, but designated vault is mockVault
      await expect(
        authManager
          .connect(otherAccount)
          .verifyAuthorization(mockVault.address, recipient.address, amount, nonce, signature)
      ).to.be.revertedWith("Caller must be vault");
    });

    it("should reject zero recipient", async function () {
      const { signature } = await generateSignature(
        mockVault.address,
        ethers.ZeroAddress,
        amount,
        nonce,
        chainId
      );

      await expect(
        authManager
          .connect(mockVault)
          .verifyAuthorization(mockVault.address, ethers.ZeroAddress, amount, nonce, signature)
      ).to.be.revertedWith("Invalid recipient");
    });

    it("should reject zero amount", async function () {
      const { signature } = await generateSignature(
        mockVault.address,
        recipient.address,
        0n,
        nonce,
        chainId
      );

      await expect(
        authManager
          .connect(mockVault)
          .verifyAuthorization(mockVault.address, recipient.address, 0n, nonce, signature)
      ).to.be.revertedWith("Invalid amount");
    });

    it("should successfully verify and consume a valid authorization", async function () {
      const { authHash, signature } = await generateSignature(
        mockVault.address,
        recipient.address,
        amount,
        nonce,
        chainId
      );

      expect(await authManager.usedAuthorizations(authHash)).to.equal(false);

      await expect(
        authManager
          .connect(mockVault)
          .verifyAuthorization(mockVault.address, recipient.address, amount, nonce, signature)
      )
        .to.emit(authManager, "AuthorizationConsumed")
        .withArgs(authHash);

      expect(await authManager.usedAuthorizations(authHash)).to.equal(true);
    });

    it("should reject replay of an already consumed authorization", async function () {
      const { authHash, signature } = await generateSignature(
        mockVault.address,
        recipient.address,
        amount,
        nonce,
        chainId
      );

      // First verification succeeds
      await authManager
        .connect(mockVault)
        .verifyAuthorization(mockVault.address, recipient.address, amount, nonce, signature);

      // Second verification attempt MUST revert deterministically
      await expect(
        authManager
          .connect(mockVault)
          .verifyAuthorization(mockVault.address, recipient.address, amount, nonce, signature)
      ).to.be.revertedWith("Authorization already used");
    });

    it("should reject signatures created by unauthorized signers", async function () {
      const { signature } = await generateSignature(
        mockVault.address,
        recipient.address,
        amount,
        nonce,
        chainId,
        unauthorizedSigner
      );

      await expect(
        authManager
          .connect(mockVault)
          .verifyAuthorization(mockVault.address, recipient.address, amount, nonce, signature)
      ).to.be.revertedWith("Invalid signature");
    });

    it("should reject when recipient parameter is altered (parameter binding)", async function () {
      const { signature } = await generateSignature(
        mockVault.address,
        recipient.address,
        amount,
        nonce,
        chainId
      );

      // Pass otherAccount instead of original recipient
      await expect(
        authManager
          .connect(mockVault)
          .verifyAuthorization(mockVault.address, otherAccount.address, amount, nonce, signature)
      ).to.be.revertedWith("Invalid signature");
    });

    it("should reject when amount parameter is altered (parameter binding)", async function () {
      const { signature } = await generateSignature(
        mockVault.address,
        recipient.address,
        amount,
        nonce,
        chainId
      );

      // Pass amount + 1 wei
      await expect(
        authManager
          .connect(mockVault)
          .verifyAuthorization(mockVault.address, recipient.address, amount + 1n, nonce, signature)
      ).to.be.revertedWith("Invalid signature");
    });

    it("should reject when nonce parameter is altered (parameter binding)", async function () {
      const { signature } = await generateSignature(
        mockVault.address,
        recipient.address,
        amount,
        nonce,
        chainId
      );

      await expect(
        authManager
          .connect(mockVault)
          .verifyAuthorization(mockVault.address, recipient.address, amount, nonce + 1n, signature)
      ).to.be.revertedWith("Invalid signature");
    });

    it("should reject authorizations signed for a different chain ID (cross-chain replay protection)", async function () {
      const wrongChainId = 1n; // Ethereum mainnet chain ID
      const { signature } = await generateSignature(
        mockVault.address,
        recipient.address,
        amount,
        nonce,
        wrongChainId
      );

      await expect(
        authManager
          .connect(mockVault)
          .verifyAuthorization(mockVault.address, recipient.address, amount, nonce, signature)
      ).to.be.revertedWith("Invalid signature");
    });
  });
});
