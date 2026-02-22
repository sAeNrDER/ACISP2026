// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ISpentSet {
    function used(bytes32 rho) external view returns (bool);
    function markUsed(bytes32 rho) external;
}
