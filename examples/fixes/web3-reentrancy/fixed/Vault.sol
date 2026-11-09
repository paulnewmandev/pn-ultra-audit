pragma solidity 0.8.24;
contract Vault {
    mapping(address => uint256) public balances;
    bool private locked;
    modifier nonReentrant() { require(!locked); locked = true; _; locked = false; }
    function withdraw(uint256 amt) public nonReentrant {
        require(balances[msg.sender] >= amt, "no funds");
        balances[msg.sender] -= amt;
        (bool ok, ) = msg.sender.call{value: amt}("");
        require(ok);
    }
}
