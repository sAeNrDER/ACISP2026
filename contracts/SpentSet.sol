// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./Authorization.sol";

contract SpentSet {
    mapping(bytes32 => bool) public used;
    Authorization public immutable authorization;

    event TokenBurned(bytes32 indexed rho, uint256 timestamp);

    constructor(address authorizationAddress) {
        authorization = Authorization(authorizationAddress);
    }

    modifier onlyAuthorizedWallet() {
        require(authorization.authorized(msg.sender), "not-authorized-wallet");
        _;
    }

    function markUsed(bytes32 rho) external onlyAuthorizedWallet {
        require(!used[rho], "Token already spent");
        used[rho] = true;
        emit TokenBurned(rho, block.timestamp);
    }
}
