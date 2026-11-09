// SPDX-License-Identifier: MIT
// INTENTIONALLY VULNERABLE - demo for PN-Ultra-Audit
pragma solidity ^0.8.0;

contract Vault {
    mapping(address => uint256) public balances;
    address public owner;
    constructor() { owner = msg.sender; }

    function deposit() external payable { balances[msg.sender] += msg.value; }

    function withdraw(uint256 amt) public {
        require(balances[msg.sender] >= amt, "no funds");
        (bool ok, ) = msg.sender.call{value: amt}("");
        balances[msg.sender] -= amt;
    }

    function sweep(address payable to) external {
        to.transfer(address(this).balance);
    }

    function isOwner() public view returns (bool) { return tx.origin == owner; }

    function pickWinner() external view returns (uint) { return uint(keccak256(abi.encodePacked(block.timestamp, msg.sender))) % 10; }

    function initialize(address o) public { owner = o; }
}
