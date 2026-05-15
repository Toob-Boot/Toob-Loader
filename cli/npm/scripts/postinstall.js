/**
 * postinstall.js — Downloads the correct Toob CLI binary for the current platform.
 *
 * Runs automatically after `npm install`. Uses only Node built-ins (zero dependencies).
 * Fetches the latest published release from GitHub, downloads the matching binary,
 * and verifies its SHA256 checksum.
 */

const https = require("https");
const fs = require("fs");
const path = require("path");
const os = require("os");
const crypto = require("crypto");

const REPO = "Toob-Boot/Toob-CLI-Release";
const RELEASE_URL = `https://api.github.com/repos/${REPO}/releases/latest`;
const BIN_DIR = path.join(__dirname, "..", "bin");

const PLATFORM_MAP = { win32: "windows", darwin: "darwin", linux: "linux" };
const ARCH_MAP = { x64: "amd64", arm64: "arm64" };

function httpGet(url) {
  return new Promise((resolve, reject) => {
    const options = {
      headers: { "User-Agent": "toob-npm-installer" },
    };
    https
      .get(url, options, (res) => {
        // Follow redirects (GitHub asset downloads return 302)
        if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
          return httpGet(res.headers.location).then(resolve, reject);
        }
        if (res.statusCode !== 200) {
          return reject(new Error(`HTTP ${res.statusCode} for ${url}`));
        }
        const chunks = [];
        res.on("data", (chunk) => chunks.push(chunk));
        res.on("end", () => resolve(Buffer.concat(chunks)));
        res.on("error", reject);
      })
      .on("error", reject);
  });
}

async function main() {
  const platform = PLATFORM_MAP[process.platform];
  const arch = ARCH_MAP[process.arch];

  if (!platform || !arch) {
    console.error(`Unsupported platform: ${process.platform}-${process.arch}`);
    console.error("Please install the Toob CLI manually from:");
    console.error("https://github.com/Toob-Boot/Toob-CLI-Release/releases");
    process.exit(1);
  }

  const ext = platform === "windows" ? ".exe" : "";
  const binaryName = `toob-${platform}-${arch}${ext}`;

  console.log(`[toob] Detecting platform: ${platform}-${arch}`);
  console.log(`[toob] Fetching latest release from GitHub...`);

  let releaseData;
  try {
    const body = await httpGet(RELEASE_URL);
    releaseData = JSON.parse(body.toString());
  } catch (err) {
    console.error(`[toob] Failed to fetch release info: ${err.message}`);
    process.exit(1);
  }

  const binaryAsset = releaseData.assets.find((a) => a.name === binaryName);
  const checksumAsset = releaseData.assets.find((a) => a.name === `${binaryName}.sha256`);

  if (!binaryAsset) {
    console.error(`[toob] No binary found for ${binaryName} in release ${releaseData.tag_name}`);
    console.error(`[toob] Available assets: ${releaseData.assets.map((a) => a.name).join(", ")}`);
    process.exit(1);
  }

  console.log(`[toob] Downloading ${binaryName} (${releaseData.tag_name})...`);

  let binaryData;
  try {
    binaryData = await httpGet(binaryAsset.browser_download_url);
  } catch (err) {
    console.error(`[toob] Download failed: ${err.message}`);
    process.exit(1);
  }

  // SHA256 verification
  if (checksumAsset) {
    console.log(`[toob] Verifying SHA256 checksum...`);
    try {
      const checksumData = await httpGet(checksumAsset.browser_download_url);
      const expectedHash = checksumData.toString().trim().split(/\s+/)[0].toLowerCase();
      const actualHash = crypto.createHash("sha256").update(binaryData).digest("hex");

      if (actualHash !== expectedHash) {
        console.error(`[toob] INTEGRITY ERROR: SHA256 mismatch!`);
        console.error(`[toob]   Expected: ${expectedHash}`);
        console.error(`[toob]   Actual:   ${actualHash}`);
        process.exit(1);
      }
      console.log(`[toob] Checksum OK.`);
    } catch (err) {
      console.error(`[toob] Warning: Could not verify checksum: ${err.message}`);
    }
  }

  // Write binary
  fs.mkdirSync(BIN_DIR, { recursive: true });
  const outputPath = path.join(BIN_DIR, `toob${ext}`);
  fs.writeFileSync(outputPath, binaryData, { mode: 0o755 });

  console.log(`[toob] Installed ${releaseData.tag_name} to ${outputPath}`);
}

main().catch((err) => {
  console.error(`[toob] Installation failed: ${err.message}`);
  process.exit(1);
});
