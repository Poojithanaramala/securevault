// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * SecureVault - on-chain control plane for encrypted cloud files.
 *
 * The file itself is encrypted in the browser and stored OFF-chain (cloud / IPFS).
 * The chain stores only: who owns a file, who may open it, a wrapped (encrypted)
 * file key per authorised user, and a hash-chained access log.
 */
contract SecureVault {
    struct FileRecord {
        address owner;
        string  cid;        // location of the encrypted blob (sha256 of ciphertext / IPFS CID)
        bytes32 fileHash;   // keccak256 of the ciphertext -> integrity check on download
        string  name;       // display name (non-sensitive)
        uint64  createdAt;
        bool    exists;
    }

    struct Grant {
        bytes   wrappedKey; // file key encrypted for the grantee's public key (ECDH)
        uint64  expiry;     // 0 = never expires
        bool    active;
    }

    enum Action { UPLOAD, GRANT, REVOKE, ACCESS, TRANSFER }

    uint256 public fileCount;
    mapping(uint256 => FileRecord) private files;
    mapping(uint256 => mapping(address => Grant)) private grants;
    mapping(address => bytes) public publicKeyOf;               // registered ECDH public key (JWK/raw bytes)
    mapping(uint256 => bytes32) public logHead;                 // tamper-evident hash chain head per file
    mapping(uint256 => uint256) public logLength;

    event KeyRegistered(address indexed user, bytes publicKey);
    event FileRegistered(uint256 indexed fileId, address indexed owner, string cid, bytes32 fileHash, string name);
    event Granted(uint256 indexed fileId, address indexed grantee, uint64 expiry);
    event Revoked(uint256 indexed fileId, address indexed grantee);
    event OwnershipTransferred(uint256 indexed fileId, address indexed from, address indexed to);
    event AccessLogged(uint256 indexed fileId, uint256 indexed index, address indexed actor, address subject, Action action, uint64 timestamp, bytes32 newHead);

    modifier onlyOwner(uint256 id) {
        require(files[id].exists, "No such file");
        require(files[id].owner == msg.sender, "Not file owner");
        _;
    }

    // ---------- identity ----------
    function registerKey(bytes calldata publicKey) external {
        require(publicKey.length > 0, "Empty key");
        publicKeyOf[msg.sender] = publicKey;
        emit KeyRegistered(msg.sender, publicKey);
    }

    // ---------- ownership ----------
    function registerFile(string calldata cid, bytes32 fileHash, string calldata name, bytes calldata ownerWrappedKey)
        external returns (uint256 id)
    {
        id = ++fileCount;
        files[id] = FileRecord(msg.sender, cid, fileHash, name, uint64(block.timestamp), true);
        grants[id][msg.sender] = Grant(ownerWrappedKey, 0, true);
        emit FileRegistered(id, msg.sender, cid, fileHash, name);
        _log(id, msg.sender, msg.sender, Action.UPLOAD);
    }

    function transferOwnership(uint256 id, address newOwner, bytes calldata newOwnerWrappedKey) external onlyOwner(id) {
        require(newOwner != address(0), "Zero address");
        address prev = msg.sender;
        grants[id][prev].active = false;
        grants[id][newOwner] = Grant(newOwnerWrappedKey, 0, true);
        files[id].owner = newOwner;
        emit OwnershipTransferred(id, prev, newOwner);
        _log(id, prev, newOwner, Action.TRANSFER);
    }

    // ---------- permissions ----------
    function grantAccess(uint256 id, address grantee, bytes calldata wrappedKey, uint64 expiry) external onlyOwner(id) {
        require(grantee != address(0), "Zero address");
        require(expiry == 0 || expiry > block.timestamp, "Expiry in past");
        grants[id][grantee] = Grant(wrappedKey, expiry, true);
        emit Granted(id, grantee, expiry);
        _log(id, msg.sender, grantee, Action.GRANT);
    }

    function revokeAccess(uint256 id, address grantee) external onlyOwner(id) {
        require(grantee != files[id].owner, "Cannot revoke owner");
        require(grants[id][grantee].active, "No active grant");
        grants[id][grantee].active = false;
        delete grants[id][grantee].wrappedKey;
        emit Revoked(id, grantee);
        _log(id, msg.sender, grantee, Action.REVOKE);
    }

    function hasAccess(uint256 id, address user) public view returns (bool) {
        Grant storage g = grants[id][user];
        return files[id].exists && g.active && (g.expiry == 0 || block.timestamp < g.expiry);
    }

    // ---------- access (reads are logged on-chain) ----------
    /// Called by an authorised user right before downloading/decrypting. Reverts if not authorised,
    /// otherwise appends to the tamper-evident log and returns what is needed to decrypt.
    function accessFile(uint256 id) external returns (string memory cid, bytes32 fileHash, bytes memory wrappedKey) {
        require(hasAccess(id, msg.sender), "Access denied");
        _log(id, msg.sender, msg.sender, Action.ACCESS);
        return (files[id].cid, files[id].fileHash, grants[id][msg.sender].wrappedKey);
    }

    // ---------- views ----------
    function getFile(uint256 id) external view returns (address owner, string memory cid, bytes32 fileHash, string memory name, uint64 createdAt) {
        FileRecord storage f = files[id];
        require(f.exists, "No such file");
        return (f.owner, f.cid, f.fileHash, f.name, f.createdAt);
    }

    function getGrant(uint256 id, address user) external view returns (bool active, uint64 expiry) {
        Grant storage g = grants[id][user];
        return (g.active, g.expiry);
    }

    // ---------- hash-chained log ----------
    // head_n = keccak256(head_{n-1}, actor, subject, action, timestamp, index). Any edit to history changes every later head,
    // and every head is also emitted as an event, so off-chain auditors can recompute and verify the whole chain.
    function _log(uint256 id, address actor, address subject, Action action) internal {
        uint256 idx = logLength[id]++;
        bytes32 newHead = keccak256(abi.encodePacked(logHead[id], actor, subject, uint8(action), uint64(block.timestamp), idx));
        logHead[id] = newHead;
        emit AccessLogged(id, idx, actor, subject, action, uint64(block.timestamp), newHead);
    }
}
