/* Client-side crypto for SecureVault. Runs unchanged in the browser and in Node 20+ (WebCrypto).
 *  - File encryption : AES-256-GCM, fresh random key + IV per file
 *  - Key sharing     : ephemeral-static ECDH (P-256) -> HKDF-SHA256 -> AES-256-GCM key wrap
 *  Private keys never leave the user's device; the chain and the cloud only see ciphertext / wrapped keys. */
(function (root) {
  const subtle = (root.crypto || require("node:crypto").webcrypto).subtle;
  const rnd = (n) => (root.crypto || require("node:crypto").webcrypto).getRandomValues(new Uint8Array(n));
  const enc = new TextEncoder();

  const toHex = (u8) => "0x" + Array.from(u8, (b) => b.toString(16).padStart(2, "0")).join("");
  const fromHex = (h) => new Uint8Array((h.replace(/^0x/, "").match(/../g) || []).map((x) => parseInt(x, 16)));
  const concat = (...a) => { const o = new Uint8Array(a.reduce((s, x) => s + x.length, 0)); let p = 0; for (const x of a) { o.set(x, p); p += x.length; } return o; };

  async function generateKeyPair() {
    const kp = await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
    const publicRaw = new Uint8Array(await subtle.exportKey("raw", kp.publicKey)); // 65 bytes
    const privateJwk = await subtle.exportKey("jwk", kp.privateKey);
    return { publicKeyHex: toHex(publicRaw), privateJwk };
  }

  async function encryptFile(plain /* Uint8Array */) {
    const fileKey = rnd(32), iv = rnd(12);
    const key = await subtle.importKey("raw", fileKey, "AES-GCM", false, ["encrypt"]);
    const ct = new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv }, key, plain));
    return { ciphertext: concat(iv, ct), fileKey };
  }

  async function decryptFile(blob /* iv||ct */, fileKey) {
    const key = await subtle.importKey("raw", fileKey, "AES-GCM", false, ["decrypt"]);
    return new Uint8Array(await subtle.decrypt({ name: "AES-GCM", iv: blob.slice(0, 12) }, key, blob.slice(12)));
  }

  async function kek(privateKey, publicKey, salt) {
    const bits = await subtle.deriveBits({ name: "ECDH", public: publicKey }, privateKey, 256);
    const hk = await subtle.importKey("raw", bits, "HKDF", false, ["deriveKey"]);
    return subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt, info: enc.encode("securevault-keywrap-v1") },
      hk, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  }

  // wrapped = ephemeralPub(65) || iv(12) || AES-GCM(fileKey)
  async function wrapKey(fileKey, recipientPublicHex) {
    const rPub = await subtle.importKey("raw", fromHex(recipientPublicHex), { name: "ECDH", namedCurve: "P-256" }, false, []);
    const eph = await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
    const ephPub = new Uint8Array(await subtle.exportKey("raw", eph.publicKey));
    const iv = rnd(12);
    const k = await kek(eph.privateKey, rPub, ephPub);
    const ct = new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv }, k, fileKey));
    return toHex(concat(ephPub, iv, ct));
  }

  async function unwrapKey(wrappedHex, privateJwk) {
    const w = fromHex(wrappedHex);
    const ephPub = w.slice(0, 65), iv = w.slice(65, 77), ct = w.slice(77);
    const priv = await subtle.importKey("jwk", privateJwk, { name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
    const ePub = await subtle.importKey("raw", ephPub, { name: "ECDH", namedCurve: "P-256" }, false, []);
    const k = await kek(priv, ePub, ephPub);
    return new Uint8Array(await subtle.decrypt({ name: "AES-GCM", iv }, k, ct));
  }

  const api = { generateKeyPair, encryptFile, decryptFile, wrapKey, unwrapKey, toHex, fromHex };
  if (typeof module !== "undefined" && module.exports) module.exports = api; else root.VaultCrypto = api;
})(typeof globalThis !== "undefined" ? globalThis : window);
