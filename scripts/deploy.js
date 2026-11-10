const hre = require("hardhat");
const fs = require("fs");
const path = require("path");
(async () => {
  const V = await hre.ethers.getContractFactory("SecureVault");
  const v = await V.deploy(); await v.waitForDeployment();
  const address = await v.getAddress();
  const artifact = await hre.artifacts.readArtifact("SecureVault");
  fs.writeFileSync(path.join(__dirname, "..", "deployment.json"), JSON.stringify({ address, abi: artifact.abi, rpc: "http://127.0.0.1:8545" }, null, 2));
  console.log("SecureVault deployed to", address);
})().catch((e) => { console.error(e); process.exit(1); });
