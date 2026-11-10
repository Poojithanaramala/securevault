// Headless end-to-end run of the same flow the UI performs, against a live local node + storage server.
const { ethers } = require("ethers");
const VC = require("../lib/crypto");
const dep = require("../deployment.json");
const BASE = process.env.BASE || "http://localhost:3000";
const assert = (c, m) => { if (!c) throw new Error("ASSERT FAILED: " + m); console.log("  ✔", m); };
(async () => {
  const p = new ethers.JsonRpcProvider(dep.rpc);
  const [o, a, m] = [await p.getSigner(0), await p.getSigner(1), await p.getSigner(3)];
  const V = (s) => new ethers.Contract(dep.address, dep.abi, s);
  const keys = {}; for (const [n, s] of [["o", o], ["a", a], ["m", m]]) { keys[n] = await VC.generateKeyPair(); const c = V(s); if ((await c.publicKeyOf(await s.getAddress())) === "0x") await (await c.registerKey(keys[n].publicKeyHex)).wait(); }

  console.log("Upload");
  const plain = new TextEncoder().encode("Confidential M.Tech dataset " + Date.now());
  const { ciphertext, fileKey } = await VC.encryptFile(plain);
  const { cid } = await (await fetch(BASE + "/blob", { method: "POST", headers: { "Content-Type": "application/octet-stream" }, body: ciphertext })).json();
  const id = Number(await V(o).fileCount()) + 1;
  await (await V(o).registerFile(cid, ethers.keccak256(ciphertext), "dataset.txt", await VC.wrapKey(fileKey, keys.o.publicKeyHex))).wait();
  const stored = new Uint8Array(await (await fetch(BASE + "/blob/" + cid)).arrayBuffer());
  assert(!Buffer.from(stored).includes(Buffer.from("Confidential")), "cloud copy contains no plaintext");

  console.log("Share with Alice, deny Mallory");
  await (await V(o).grantAccess(id, await a.getAddress(), await VC.wrapKey(fileKey, keys.a.publicKeyHex), 0)).wait();
  const [c1, h1, w1] = await V(a).accessFile.staticCall(id); await (await V(a).accessFile(id)).wait();
  const dec = await VC.decryptFile(new Uint8Array(await (await fetch(BASE + "/blob/" + c1)).arrayBuffer()), await VC.unwrapKey(w1, keys.a.privateJwk));
  assert(new TextDecoder().decode(dec) === new TextDecoder().decode(plain), "Alice decrypts the original file");
  let denied = false; try { await V(m).accessFile.staticCall(id); } catch { denied = true; }
  assert(denied, "Mallory is rejected by the smart contract");

  console.log("Revoke");
  await (await V(o).revokeAccess(id, await a.getAddress())).wait();
  denied = false; try { await V(a).accessFile.staticCall(id); } catch { denied = true; }
  assert(denied, "Alice is rejected after revocation");

  console.log("Cloud tampering");
  await fetch(BASE + "/demo/tamper/" + cid, { method: "POST" });
  const bad = new Uint8Array(await (await fetch(BASE + "/blob/" + cid)).arrayBuffer());
  assert(ethers.keccak256(bad) !== h1, "on-chain hash exposes the modified cloud copy");

  console.log("Audit chain");
  const ev = await V(o).queryFilter(V(o).filters.AccessLogged(id)); let head = ethers.ZeroHash;
  for (const e of ev) head = ethers.solidityPackedKeccak256(["bytes32", "address", "address", "uint8", "uint64", "uint256"], [head, e.args.actor, e.args.subject, e.args.action, e.args.timestamp, e.args.index]);
  assert(head === (await V(o).logHead(id)) && ev.length === 4, `log of ${ev.length} entries recomputes to on-chain head`);
  console.log("\nE2E PASSED");
})().catch((e) => { console.error(e); process.exit(1); });
