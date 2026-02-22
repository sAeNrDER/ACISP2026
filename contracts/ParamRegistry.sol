// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ParamRegistry {
    bytes public immutable pkCA;
    uint8 public immutable t;
    uint8 public immutable n;

    constructor(bytes memory _pkCA, uint8 _t, uint8 _n) {
        require(_pkCA.length == 64, "pk-len");
        pkCA = _pkCA;
        t = _t;
        n = _n;
    }

    function getPublicKey() external view returns (bytes memory) {
        return pkCA;
    }

    function getThresholdConfig() external view returns (uint8, uint8) {
        return (t, n);
    }
}
