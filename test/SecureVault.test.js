const { expect } = require("chai");
const { ethers } = require("hardhat");
const { time } = require("@nomicfoundation/hardhat-network-helpers");
const VC = require("../lib/crypto");

describe("SecureVault", () => {
  let vault, owner, alice, bob, mallory;
  beforeEach(async () => {
    [owner, alice, bob, mallory] = await ethers.getSigners();
    vault = await (await ethers.getContractFactory("SecureVault")).deploy();
    await vault.connect(owner).registerFile("cid1", ethers.keccak256("0x1234"), "report.pdf", "0xaa");
  });

  it("records ownership and an UPLOAD log entry", async () => {
    const f = await vault.getFile(1);
    expect(f.owner).to.equal(owner.address);
    expect(f.name).to.equal("report.pdf");
    expect(await vault.logLength(1)).to.equal(1);
    expect(await vault.hasAccess(1, owner.address)).to.equal(true);
  });

  it("only the owner can grant / revoke", async () => {
    await expect(vault.connect(mallory).grantAccess(1, mallory.address, "0xbb", 0)).to.be.revertedWith("Not file owner");
    await vault.grantAccess(1, alice.address, "0xbb", 0);
    await expect(vault.connect(mallory).revokeAccess(1, alice.address)).to.be.revertedWith("Not file owner");
  });

  it("authorised user can access; stranger is denied and gets no key", async () => {
    await vault.grantAccess(1, alice.address, "0xbb", 0);
    expect(await vault.connect(alice).accessFile.staticCall(1)).to.deep.equal(["cid1", ethers.keccak256("0x1234"), "0xbb"]);
    await expect(vault.connect(mallory).accessFile(1)).to.be.revertedWith("Access denied");
  });

  it("revoked user loses access immediately", async () => {
    await vault.grantAccess(1, alice.address, "0xbb", 0);
    await vault.connect(alice).accessFile(1);
    await vault.revokeAccess(1, alice.address);
    await expect(vault.connect(alice).accessFile(1)).to.be.revertedWith("Access denied");
  });

  it("time-limited grants expire", async () => {
    const exp = (await time.latest()) + 3600;
    await vault.grantAccess(1, bob.address, "0xcc", exp);
    expect(await vault.hasAccess(1, bob.address)).to.equal(true);
    await time.increaseTo(exp + 1);
    expect(await vault.hasAccess(1, bob.address)).to.equal(false);
    await expect(vault.connect(bob).accessFile(1)).to.be.revertedWith("Access denied");
  });

  it("ownership transfer moves control to the new owner", async () => {
    await vault.transferOwnership(1, alice.address, "0xdd");
    expect((await vault.getFile(1)).owner).to.equal(alice.address);
    expect(await vault.hasAccess(1, owner.address)).to.equal(false);
    await expect(vault.grantAccess(1, bob.address, "0xee", 0)).to.be.revertedWith("Not file owner");
    await vault.connect(alice).grantAccess(1, bob.address, "0xee", 0);
  });

  it("access log is a hash chain that an auditor can recompute from events", async () => {
    await vault.grantAccess(1, alice.address, "0xbb", 0);
    await vault.connect(alice).accessFile(1);
    await vault.revokeAccess(1, alice.address);
    const events = await vault.queryFilter(vault.filters.AccessLogged(1));
    expect(events.length).to.equal(4);
    let head = ethers.ZeroHash;
    for (const e of events) {
      const { index, actor, subject, action, timestamp, newHead } = e.args;
      head = ethers.solidityPackedKeccak256(["bytes32", "address", "address", "uint8", "uint64", "uint256"], [head, actor, subject, action, timestamp, index]);
      expect(head).to.equal(newHead);
    }
    expect(head).to.equal(await vault.logHead(1)); // a forged / dropped / reordered entry would break this
  });

  it("end-to-end crypto: wrapped key only opens for the intended recipient", async () => {
    const a = await VC.generateKeyPair(), m = await VC.generateKeyPair();
    const plain = new TextEncoder().encode("top secret thesis data");
    const { ciphertext, fileKey } = await VC.encryptFile(plain);
    const wrapped = await VC.wrapKey(fileKey, a.publicKeyHex);
    const k = await VC.unwrapKey(wrapped, a.privateJwk);
    expect(new TextDecoder().decode(await VC.decryptFile(ciphertext, k))).to.equal("top secret thesis data");
    await expect(VC.unwrapKey(wrapped, m.privateJwk)).to.be.rejected;
    const bad = ciphertext.slice(); bad[bad.length - 1] ^= 1;               // tampered cloud copy
    await expect(VC.decryptFile(bad, k)).to.be.rejected;
  });
});
