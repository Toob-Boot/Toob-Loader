#!/usr/bin/env node

// Thin shim that forwards all CLI arguments to the native Toob Go binary.
// This exists because npm's "bin" field requires a Node.js entry point.

const { execFileSync } = require("child_process");
const path = require("path");
const os = require("os");

const ext = os.platform() === "win32" ? ".exe" : "";
const binary = path.join(__dirname, `toob${ext}`);

try {
  execFileSync(binary, process.argv.slice(2), { stdio: "inherit" });
} catch (err) {
  if (err.status !== undefined) {
    process.exit(err.status);
  }
  console.error(`Failed to execute toob binary at ${binary}`);
  console.error("Try reinstalling: npm install -g toob");
  process.exit(1);
}
