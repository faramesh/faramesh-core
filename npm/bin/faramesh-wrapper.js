#!/usr/bin/env node
"use strict";

const { execFileSync } = require("child_process");
const path = require("path");
const os = require("os");
const fs = require("fs");

const ext = os.platform() === "win32" ? ".exe" : "";
const binPath = path.join(__dirname, `faramesh${ext}`);

if (!fs.existsSync(binPath)) {
  console.error("faramesh binary not found. Reinstall with: npm install -g @faramesh/cli");
  console.error("Or install directly: curl -fsSL https://install.faramesh.dev/install.sh | bash");
  process.exit(1);
}

try {
  execFileSync(binPath, process.argv.slice(2), { stdio: "inherit" });
} catch (err) {
  process.exit(err.status || 1);
}
