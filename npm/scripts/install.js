#!/usr/bin/env node
"use strict";

const { execSync } = require("child_process");
const fs = require("fs");
const path = require("path");
const https = require("https");
const os = require("os");

const VERSION = require("../package.json").version;
const BIN_DIR = path.join(__dirname, "..", "bin");

const PLATFORM_MAP = {
  darwin: "darwin",
  linux: "linux",
  win32: "windows",
};

const ARCH_MAP = {
  x64: "amd64",
  arm64: "arm64",
};

function getDownloadUrl() {
  const platform = PLATFORM_MAP[os.platform()];
  const arch = ARCH_MAP[os.arch()];

  if (!platform || !arch) {
    console.error(`Unsupported platform: ${os.platform()} ${os.arch()}`);
    process.exit(1);
  }

  const ext = platform === "windows" ? ".exe" : "";
  return `https://github.com/faramesh/faramesh-core/releases/download/v${VERSION}/faramesh-${platform}-${arch}${ext}`;
}

function download(url, dest) {
  return new Promise((resolve, reject) => {
    const file = fs.createWriteStream(dest);
    https
      .get(url, (response) => {
        if (response.statusCode === 302 || response.statusCode === 301) {
          download(response.headers.location, dest).then(resolve).catch(reject);
          return;
        }
        if (response.statusCode !== 200) {
          reject(new Error(`Download failed: HTTP ${response.statusCode}`));
          return;
        }
        response.pipe(file);
        file.on("finish", () => {
          file.close(resolve);
        });
      })
      .on("error", reject);
  });
}

async function main() {
  const url = getDownloadUrl();
  const ext = os.platform() === "win32" ? ".exe" : "";
  const binPath = path.join(BIN_DIR, `faramesh${ext}`);

  fs.mkdirSync(BIN_DIR, { recursive: true });

  console.log(`Downloading faramesh v${VERSION}...`);
  console.log(`  ${url}`);

  try {
    await download(url, binPath);
    fs.chmodSync(binPath, 0o755);
    console.log(`Installed faramesh to ${binPath}`);
  } catch (err) {
    console.error(`Failed to download faramesh binary: ${err.message}`);
    console.error("You can install manually: curl -fsSL https://raw.githubusercontent.com/faramesh/faramesh-core/main/install.sh | bash && faramesh setup flow");
    process.exit(1);
  }
}

main();
