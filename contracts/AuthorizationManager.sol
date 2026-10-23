// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import "./interfaces/IAuthorizationManager.sol";

/**
 * @title AuthorizationManager
 * @author sucha6174
 * @notice Validates off-chain cryptographic authorizations for vault withdrawals and enforces single-use replay protection.
 *
 * @custom:invariant INV-AUTH-1: Each valid authorization can only trigger state consumption exactly once.
 * @custom:invariant INV-AUTH-2: Only valid ECDSA signatures produced by the designated trusted signer are accepted.
 * @custom:invariant INV-AUTH-3: Authorizations are strictly bound to vault, recipient, amount, nonce, and network chainId.
 * @custom:invariant INV-AUTH-4: Only the designated vault contract can call `verifyAuthorization` for its own withdrawals.
 * @custom:invariant INV-AUTH-5: Initialization can only be executed once, and exclusively by the authorized contract owner.
 * @custom:invariant INV-AUTH-6: Zero-address signers, vaults, or recipients, and zero withdrawal amounts are rejected.
 */
contract AuthorizationManager is IAuthorizationManager, Ownable {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    /// @notice Address of the trusted off-chain signer entity.
    address public signer;

    /// @notice Tracks whether the contract initialization has been completed.
    bool public initialized;

    /// @notice Tracks consumed authorization hashes to guarantee single-use replay protection.
    mapping(bytes32 => bool) public override usedAuthorizations;

    /**
     * @notice Initializes contract deployer as the initial owner.
     * @dev Explicit access control via OpenZeppelin Ownable ensures only deployer can initialize.
     */
    constructor() Ownable(msg.sender) {}

    /**
     * @notice Initializes the contract with the trusted signer address.
     * @dev Protected by `onlyOwner` to prevent front-running attacks during deployment.
     * @param _signer The address of the trusted off-chain signer key.
     */
    function initialize(address _signer) external onlyOwner {
        require(!initialized, "Already initialized");
        require(_signer != address(0), "Invalid signer address");

        signer = _signer;
        initialized = true;
    }

    /**
     * @notice Allows the contract owner to rotate the trusted signer address.
     * @param _newSigner The new trusted signer address.
     */
    function setSigner(address _newSigner) external onlyOwner {
        require(_newSigner != address(0), "Invalid signer address");
        signer = _newSigner;
    }

    /**
     * @notice Computes deterministic keccak256 hash of withdrawal parameters.
     * @param vault Address of the custody vault.
     * @param recipient Target address receiving the withdrawal.
     * @param amount Amount of funds in wei.
     * @param nonce Unique authorization identifier.
     * @param chainId Target network chain ID.
     * @return Deterministic 32-byte authorization hash.
     */
    function getAuthHash(
        address vault,
        address recipient,
        uint256 amount,
        uint256 nonce,
        uint256 chainId
    ) public pure override returns (bytes32) {
        return keccak256(abi.encodePacked(vault, recipient, amount, nonce, chainId));
    }

    /**
     * @notice Verifies cryptographic authorization and marks it as consumed.
     * @dev Callable exclusively by the designated vault contract. Uses OpenZeppelin ECDSA for secure signature recovery.
     * @param vault The vault address initiating the withdrawal.
     * @param recipient The recipient address receiving the funds.
     * @param amount The withdrawal amount in wei.
     * @param nonce The unique nonce for this withdrawal authorization.
     * @param signature The 65-byte ECDSA signature over the Ethereum signed message hash.
     * @return True if authorization is authentic, unconsumed, and successfully marked as consumed.
     */
    function verifyAuthorization(
        address vault,
        address recipient,
        uint256 amount,
        uint256 nonce,
        bytes calldata signature
    ) external override returns (bool) {
        require(initialized, "Not initialized");
        require(msg.sender == vault, "Caller must be vault");
        require(recipient != address(0), "Invalid recipient");
        require(amount > 0, "Invalid amount");

        // Deterministic hash computed using the current blockchain chain ID
        bytes32 authHash = getAuthHash(vault, recipient, amount, nonce, block.chainid);

        // Replay protection: ensure authorization has not been consumed
        require(!usedAuthorizations[authHash], "Authorization already used");

        // Recover signer using audited OpenZeppelin cryptography
        bytes32 ethSignedHash = authHash.toEthSignedMessageHash();
        address recoveredSigner = ECDSA.recover(ethSignedHash, signature);

        require(recoveredSigner == signer, "Invalid signature");

        // State update: Mark authorization consumed before returning (Checks-Effects)
        usedAuthorizations[authHash] = true;

        emit AuthorizationConsumed(authHash);

        return true;
    }
}
