// "Cloud" storage stand-in: stores ONLY ciphertext, addressed by sha256. Swap for S3 / IPFS (Pinata) in production.
const express = require("express");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const ROOT = path.join(__dirname, "..");
const STORE = path.join(ROOT, "storage");
fs.mkdirSync(STORE, { recursive: true });

const app = express();
app.use("/", express.static(path.join(ROOT, "public")));
app.use("/lib", express.static(path.join(ROOT, "lib")));
app.get("/vendor/ethers.js", (_q, r) => r.sendFile(path.join(ROOT, "node_modules/ethers/dist/ethers.umd.min.js")));
app.get("/deployment.json", (_q, r) => r.sendFile(path.join(ROOT, "deployment.json")));

app.post("/blob", express.raw({ type: "*/*", limit: "50mb" }), (req, res) => {
  const cid = crypto.createHash("sha256").update(req.body).digest("hex");
  fs.writeFileSync(path.join(STORE, cid), req.body);
  res.json({ cid });
});
app.get("/blob/:cid", (req, res) => {
  const f = path.join(STORE, path.basename(req.params.cid));
  if (!fs.existsSync(f)) return res.status(404).end();
  res.type("application/octet-stream").send(fs.readFileSync(f));
});
// DEMO ONLY: simulate a malicious/compromised cloud provider flipping a byte of a stored file.
app.post("/demo/tamper/:cid", (req, res) => {
  const f = path.join(STORE, path.basename(req.params.cid));
  if (!fs.existsSync(f)) return res.status(404).end();
  const b = fs.readFileSync(f); b[b.length - 1] ^= 0xff; fs.writeFileSync(f, b);
  res.json({ tampered: true });
});

const PORT = process.env.PORT || 3000;
if (require.main === module) app.listen(PORT, () => console.log(`SecureVault app + storage on http://localhost:${PORT}`));
module.exports = app;
