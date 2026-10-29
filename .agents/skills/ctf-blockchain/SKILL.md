---
name: ctf-blockchain
description: >-
  Activate this skill when a CTF challenge involves blockchain, smart contracts,
  Ethereum/Solidity exploitation, or cryptocurrency analysis. HI CyberCon CTF
  2026 includes a Blockchain category covering smart contracts and chains.
---

# CTF Blockchain / Smart Contract Skill

## Phase 1 — Recon
```bash
# Identify network
# Mainnet? Testnet (Sepolia, Goerli)? Local Ganache/Anvil?

# Read contract from block explorer
# Etherscan: https://etherscan.io/address/<address>#code
# Get ABI and bytecode

# If no source: decompile
# Panoramix: pip install panoramix-decompiler
panoramix <bytecode>
# Or: https://app.dedaub.com/decompile
```

## Phase 2 — Common Vulnerability Classes

### Reentrancy
```solidity
// Vulnerable: state updated AFTER external call
function withdraw() external {
    uint amount = balances[msg.sender];
    (bool ok,) = msg.sender.call{value: amount}(""); // ← attacker re-enters here
    balances[msg.sender] = 0;                          // ← too late
}
// Attack: deploy contract with fallback() that calls withdraw() again
```

### Integer Overflow / Underflow (pre-Solidity 0.8)
```solidity
uint8 x = 0;
x -= 1;  // → 255 (wraps around)
// Use: manipulate balances, bypass checks
```

### Access Control / tx.origin Auth
```solidity
require(tx.origin == owner);  // ← vulnerable: any contract can satisfy this
// vs. msg.sender (correct)
```

### Delegatecall Proxy Issues
```solidity
// Storage slot collision between proxy and implementation
// Override owner by calling initialize() on uninitialized proxy
```

### Selfdestruct to Force-Send ETH
```solidity
// Send ETH to contract that doesn't expect it
// Break invariants like: require(address(this).balance == 0)
```

### Timestamp / Block Manipulation
```solidity
require(block.timestamp % 15 == 0);  // guessable/manipulable
```

### Flash Loan Attacks
```python
# Borrow huge amount → manipulate price oracle → profit → repay in one tx
```

### Signature Replay
```python
# Reuse a valid signed message across chains or contexts
```

## Phase 3 — Exploitation Tools
```bash
# Foundry (Forge + Cast + Anvil)
forge test --fork-url <rpc_url>
cast send <contract> "functionName(args)" --private-key <key>
cast call <contract> "view_function()" --rpc-url <url>

# Hardhat
npx hardhat console --network <network>

# Python + web3.py
from web3 import Web3
w3 = Web3(Web3.HTTPProvider('<rpc_url>'))
contract = w3.eth.contract(address='<addr>', abi=<abi>)
contract.functions.flag().call()
```

## Phase 4 — Flag Extraction Patterns
```python
# Flags often stored as:
# - bytes32 storage variable
# - emit FlagCaptured(string flag) event
# - return value of solve() function
# - hidden in contract source comments

# Read storage slots directly
cast storage <contract_addr> 0  # slot 0
cast storage <contract_addr> 1  # slot 1, etc.

# Decode bytes32 → string
import web3
w3 = web3.Web3()
val = w3.eth.get_storage_at('<addr>', 0)
print(val.decode('utf-8', errors='replace').strip('\x00'))
```

## Phase 5 — On-Chain Analysis
```bash
# Read all events from contract
cast logs --address <contract> --from-block 0 --to-block latest

# Trace a transaction
cast run <tx_hash> --rpc-url <url>
cast decode-calldata "solve(bytes32)" <calldata>
```

## Structured Output
```json
{
  "agent": "ctf-blockchain",
  "contract_address": "",
  "network": "",
  "vuln_class": "",
  "exploit_tx": "",
  "flag_candidates": [],
  "confidence": 0.0
}
```
