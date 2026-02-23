// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "./interfaces/ISpentSet.sol";

contract BiometricWallet {
    using ECDSA for bytes32;

    bytes4 internal constant MAGICVALUE = 0x1626ba7e;
    address public immutable owner;
    ISpentSet public immutable spentSet;

    bytes32 private constant DOMAIN_NAME = keccak256("BiometricWallet");
    bytes32 private constant DOMAIN_VERSION = keccak256("1");

    constructor(address _owner, address spentSetAddress) {
        owner = _owner;
        spentSet = ISpentSet(spentSetAddress);
    }

    function isValidSignature(bytes32 hash, bytes memory signature) public view returns (bytes4) {
        address signer = ECDSA.recover(hash, signature);
        return signer == owner ? MAGICVALUE : bytes4(0xffffffff);
    }

    function authenticate(bytes32 rho, bytes32 userOpHash, bytes calldata signature) external {
        require(!spentSet.used(rho), "spent");
        bytes32 typedHash = keccak256(
            abi.encodePacked(
                "\x19\x01",
                keccak256(abi.encode(DOMAIN_NAME, DOMAIN_VERSION, block.chainid, address(this))),
                keccak256(abi.encode(rho, userOpHash))
            )
        );
        require(isValidSignature(typedHash, signature) == MAGICVALUE, "bad-signature");
        spentSet.markUsed(rho);
    }
}
