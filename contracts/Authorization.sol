// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Authorization {
    mapping(address => bool) public authorized;
    address public owner;

    event AuthorizationUpdated(address indexed wallet, bool status);

    constructor(address _owner) {
        owner = _owner;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not-owner");
        _;
    }

    function setAuthorized(address wallet, bool status) external onlyOwner {
        authorized[wallet] = status;
        emit AuthorizationUpdated(wallet, status);
    }
}
