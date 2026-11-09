pragma solidity 0.8.24;
contract Vault {
    mapping(address => uint256) public balances;
    function withdraw(uint256 amt) public {
        require(balances[msg.sender] >= amt, "no funds");
        (bool ok, ) = msg.sender.call{value: amt}("");
        require(ok);
        balances[msg.sender] -= amt;
    }
}
