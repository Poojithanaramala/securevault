# SecureVault – blockchain-secured cloud file sharing

**Problem:** cloud file sharing relies on a central server for access control, so the provider (or an attacker who breaks in) can read files, change permissions and rewrite access history.

**Solution:** files are encrypted *in the browser*; a smart contract (not a server) decides who owns a file and who may open it; every action is written to a hash-chained log on the blockchain that anyone can re-verify.

```
Browser (AES-256-GCM encrypt)  ──ciphertext──▶  Cloud storage (sees only random bytes)
        │  wrapped file key + keccak256(ciphertext)
        ▼
SecureVault.sol  (ownership · grant/revoke/expiry · transfer · hash-chained access log)
        ▲
Recipient: calls accessFile() → contract checks permission, logs it, returns wrapped key
           → fetch ciphertext → verify hash → unwrap key (own private key) → decrypt locally
```

| Requirement | How it is met |
|---|---|
| Encrypt and store files in the cloud | AES-256-GCM in browser (`lib/crypto.js`); `server/server.js` stores only ciphertext (stand-in for S3/IPFS) |
| Blockchain smart contracts manage ownership | `registerFile`, `transferOwnership` |
| …permissions | `grantAccess` (optional expiry), `revokeAccess`, `hasAccess`; file key wrapped per user with ECDH (P-256) |
| …sharing | owner re-wraps the file key for the recipient's registered public key; no key ever travels in plaintext |
| Tamper-resistant access history | every UPLOAD/GRANT/REVOKE/ACCESS/TRANSFER extends `head = keccak256(prevHead, actor, subject, action, time, index)`; UI "Verify log" recomputes the chain from events and compares with the on-chain head |
| Cloud provider tampering | `keccak256(ciphertext)` stored on-chain; download is refused if the cloud copy differs |

## Run it (5 minutes)

```bash
npm install
npm test            # 8 smart-contract + crypto tests
./scripts/start-demo.sh      # local chain + deploy + app  →  open http://localhost:3000
# in a second terminal (optional): npm run e2e
```
If Hardhat can't download the Solidity compiler it falls back automatically to the bundled `solc` package. Set `USE_NATIVE_SOLC=1` to use the normal download.

## Demo script for your presentation (about 8 minutes)

1. **Problem (1 min).** Central access control = single point of failure; admin can read files and edit logs.
2. **Upload as *Owner*.** Pick a file → "Encrypt & Upload". Point out: cloud holds only ciphertext; ownership is now on-chain.
3. **Share with *Alice*, 10-minute expiry.** Switch to Alice → *Download & decrypt* works; file opens.
4. **Switch to *Mallory* (attacker)** → Download → "Access denied" from the smart contract.
5. **Back to Owner → Revoke Alice**, switch to Alice → denied immediately.
6. **"Simulate cloud tampering"** then download as Owner → "INTEGRITY CHECK FAILED".
7. **Audit trail → Verify log:** every step listed with actor, time and chained hash, "Chain verified ✔". Explain: editing any past entry changes all later hashes, and the events are replicated by every node.
8. **Show `SecureVault.sol` (≈100 lines)** and the passing `npm test`.

## One-day build plan (if you want to rebuild or extend it yourself)

| Time | Task |
|---|---|
| 1 h | Read the SHIELD README; list its gaps (no ownership registry, no revoke, single recipient) |
| 2 h | Write the contract + Hardhat tests (`contracts/`, `test/`) |
| 1.5 h | Crypto: AES-GCM file encryption + ECDH key wrapping (`lib/crypto.js`) |
| 1 h | Storage server (S3 / Pinata IPFS in production) |
| 2 h | Web UI with ethers.js (+ MetaMask/RainbowKit for real wallets) |
| 1 h | End-to-end test, rehearse the demo, screenshots |
| 1.5 h | Slides: architecture, threat model, test results |

## Likely viva questions

- **Why not put the file on the blockchain?** Too expensive and public; chain stores only metadata, hashes and wrapped keys.
- **Can the cloud or the blockchain read my file?** No: they only ever see ciphertext and keys encrypted for specific users.
- **What does the blockchain add over a database?** Permissions and log aren't controlled by one admin; history can't be silently edited and anyone can re-verify it.
- **What does revoke guarantee?** No future key delivery or logged access. It cannot un-leak a key someone already used; for that, re-encrypt the file with a new key and re-wrap for remaining users.
- **Gas cost?** Each upload/grant/access is one transaction; deploy to an L2 (Base, Polygon) to make it cheap.

## Known limitations (be upfront about these)

- Demo mode: one browser holds the keys of four local test accounts and uses Hardhat's unlocked accounts. Production: MetaMask/WalletConnect for signing and each user keeps their own private key (or derives it from a wallet signature).
- On-chain data is public: file name, owner, grantee addresses and timing are visible; file contents and keys are not.
- `accessFile` costs gas because reads are logged on-chain; that is intentional for the audit trail.
- Storage server is a local stand-in with no authentication; swap for S3/IPFS.
- The contract has not been security-audited.

Inspired by the open-source SHIELD dApp (https://github.com/optimusexe/SHIELD, MIT licence).
