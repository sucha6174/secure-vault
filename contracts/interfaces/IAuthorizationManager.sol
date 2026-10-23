// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title IAuthorizationManager
 * @author sucha6174
 * @notice Interface for the AuthorizationManager contract governing withdrawal permissions.
 */
interface IAuthorizationManager {
    /**
     * @notice Emitted when a withdrawal authorization is successfully verified and consumed.
     * @param authHash The deterministic hash of the consumed authorization parameters.
     */
    event AuthorizationConsumed(bytes32 indexed authHash);

    /**
     * @notice Computes the deterministic 32-byte authorization hash.
     * @param vault The address of the vault holding funds.
     * @param recipient The destination address for the withdrawn funds.
     * @param amount The withdrawal amount in wei.
     * @param nonce The unique nonce to guarantee single-use.
     * @param chainId The target blockchain network chain ID.
     * @return The computed keccak256 authorization hash.
     */
    function getAuthHash(
        address vault,
        address recipient,
        uint256 amount,
        uint256 nonce,
        uint256 chainId
    ) external pure returns (bytes32);

    /**
     * @notice Verifies cryptographic authorization and marks it as consumed in a single state transition.
     * @dev Must only be callable by the designated vault address.
     * @param vault The address of the vault executing the withdrawal.
     * @param recipient The intended recipient address.
     * @param amount The amount to be withdrawn in wei.
     * @param nonce The unique authorization identifier.
     * @param signature The ECDSA signature over the Ethereum signed message hash.
     * @return True if authorization is valid and marked consumed.
     */
    function verifyAuthorization(
        address vault,
        address recipient,
        uint256 amount,
        uint256 nonce,
        bytes calldata signature
    ) external returns (bool);

    /**
     * @notice Checks whether a given authorization hash has already been consumed.
     * @param authHash The authorization hash to check.
     * @return True if consumed, false otherwise.
     */
    function usedAuthorizations(bytes32 authHash) external view returns (bool);
}
