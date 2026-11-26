// End-to-end test of the code generator: for each server language and a set
// of option scenarios, generate the app, build and start it, and drive real
// ceremonies in Chromium with a virtual authenticator.
//
// Usage: npm test [-- LANG...]

import { spawn, execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { chromium } from "playwright";

const repo = resolve(import.meta.dirname, "..");

// The .NET SDK is often installed per user, outside PATH.
const dotnetHome = join(homedir(), ".dotnet");
if (existsSync(dotnetHome)) process.env.PATH = `${dotnetHome}:${process.env.PATH}`;
process.env.DOTNET_CLI_TELEMETRY_OPTOUT = "1";
process.env.DOTNET_NOLOGO = "1";
const work = mkdtempSync(join(tmpdir(), "passkeys-e2e-"));
const tool = join(work, "passkeys-test");

// Each scenario lists the spec, the authenticator, and the flows to check.
const scenarios = [
  {
    name: "defaults, autofill",
    spec: {},
    flows: ["register", "add-excluded", "autofill"],
  },
  {
    name: "security key, PRF, UV required, hints",
    spec: { conditionalUI: false, prf: true, hints: ["security-key"], attachment: "cross-platform", userVerification: "required", attestation: "indirect" },
    flows: ["register", "username", "discoverable"],
  },
  {
    name: "non-discoverable, no UV, direct attestation, no exclusions",
    spec: { conditionalUI: false, residentKey: "discouraged", userVerification: "discouraged", attestation: "direct", excludeExisting: false },
    flows: ["register", "add-allowed", "username"],
  },
  {
    name: "platform authenticator, residentKey preferred",
    spec: { conditionalUI: false, attachment: "platform", residentKey: "preferred", hints: ["client-device"], credProps: false },
    flows: ["register", "discoverable"],
  },
];

const targets = {
  go: { build: [["go", "mod", "tidy"], ["go", "build", "-o", "app", "."]], start: ["./app"] },
  node: { build: [["npm", "install", "--no-audit", "--no-fund", "--silent"]], start: ["node", "server.js"] },
  csharp: {
    build: [["dotnet", "build", "-nologo", "-v", "q", "-c", "Release", "-o", "out"]],
    start: ["dotnet", "out/Passkeys.dll"],
  },
  java: { build: [["mvn", "-q", "-B", "package", "-DskipTests"]], start: ["java", "-jar", "target/passkeys.jar"] },
  python: {
    build: [["python3", "-m", "venv", ".venv"], [".venv/bin/pip", "install", "-q", "-r", "requirements.txt"]],
    start: [".venv/bin/python", "server.py"],
  },
};

const langs = process.argv.slice(2).length ? process.argv.slice(2) : Object.keys(targets);
for (const l of langs) if (!targets[l]) throw new Error(`unknown language ${l}`);

execFileSync("go", ["build", "-o", tool, "."], { cwd: repo, stdio: "inherit" });
const browser = await chromium.launch();
const results = [];
let port = 3100;

try {
  for (const lang of langs) {
    for (const sc of scenarios) {
      port++;
      const label = `${lang}: ${sc.name}`;
      const t0 = Date.now();
      try {
        await runScenario(lang, sc, port);
        results.push({ label, ok: true, ms: Date.now() - t0 });
        console.log(`PASS  ${label}`);
      } catch (e) {
        results.push({ label, ok: false, error: e.message });
        console.log(`FAIL  ${label}\n      ${e.message.split("\n").join("\n      ")}`);
      }
    }
  }
} finally {
  await browser.close();
  rmSync(work, { recursive: true, force: true });
}

const failed = results.filter((r) => !r.ok).length;
console.log(`\n${results.length - failed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);

async function runScenario(lang, sc, port) {
  const origin = `http://localhost:${port}`;
  const dir = join(work, `${lang}-${port}`);
  const spec = JSON.stringify({ ...sc.spec, origin });
  execFileSync(tool, ["codegen", "-lang", lang, "-out", dir, "-spec", spec], { stdio: "pipe" });
  for (const [cmd, ...args] of targets[lang].build) {
    execFileSync(cmd, args, { cwd: dir, stdio: "pipe" });
  }

  const [cmd, ...args] = targets[lang].start;
  const server = spawn(cmd, args, { cwd: dir, env: { ...process.env, PORT: String(port) }, stdio: ["ignore", "pipe", "pipe"] });
  let serverLog = "";
  server.stdout.on("data", (d) => (serverLog += d));
  server.stderr.on("data", (d) => (serverLog += d));

  const context = await browser.newContext();
  if (sc.spec.conditionalUI !== false) {
    // Headless Chromium reports conditional mediation as unavailable, but
    // serves conditional requests from the virtual authenticator.
    await context.addInitScript(() => {
      PublicKeyCredential.isConditionalMediationAvailable = async () => true;
    });
  }
  try {
    await waitForServer(origin);
    const page = await context.newPage();
    const cdp = await context.newCDPSession(page);
    await cdp.send("WebAuthn.enable");
    await cdp.send("WebAuthn.addVirtualAuthenticator", {
      options: {
        protocol: "ctap2",
        ctap2Version: "ctap2_1",
        transport: sc.spec.attachment === "platform" ? "internal" : "usb",
        hasResidentKey: true,
        hasUserVerification: true,
        isUserVerified: true,
        hasPrf: true,
        automaticPresenceSimulation: true,
      },
    });
    await page.goto(origin);
    const prf = !!sc.spec.prf;

    for (const flow of sc.flows) {
      try {
        switch (flow) {
          case "register":
            await signedOut(page);
            await page.fill("#username", "alice");
            await page.click("#register");
            await signedInAs(page, "alice");
            await serverUser(page, "alice");
            if (prf) await statusContains(page, "PRF supported");
            break;
          case "add-excluded":
            await page.click("#add-passkey");
            await page.waitForSelector("#status.error", { timeout: 10000 });
            await passkeyCount(page, 1);
            break;
          case "add-allowed":
            await page.click("#add-passkey");
            await statusContains(page, "Passkey added");
            await passkeyCount(page, 2);
            break;
          case "autofill":
            // Signing out restarts autofill, which the virtual authenticator
            // answers right away. The page still shows the old session for a
            // moment, so wait for a fresh sign-in message and ask the server.
            await page.evaluate(() => (document.getElementById("status").textContent = ""));
            await page.click("#signout");
            await statusContains(page, "Signed in as alice");
            await signedInAs(page, "alice");
            await serverUser(page, "alice");
            break;
          case "username":
            await signOut(page);
            await page.fill("#username", "alice");
            await page.click("#signin");
            await signedInAs(page, "alice");
            await serverUser(page, "alice");
            if (prf) await statusContains(page, "PRF secret derived");
            break;
          case "discoverable":
            await signOut(page);
            await page.fill("#username", "");
            await page.click("#signin");
            await signedInAs(page, "alice");
            await serverUser(page, "alice");
            if (prf) await statusContains(page, "PRF secret derived");
            break;
          default:
            throw new Error(`unknown flow ${flow}`);
        }
      } catch (e) {
        const status = await page.textContent("#status").catch(() => "");
        throw new Error(`${flow}: ${e.message.split("\n")[0]}\nstatus: ${status}\nserver log:\n${serverLog.trim().split("\n").slice(-8).join("\n")}`);
      }
    }
  } finally {
    await context.close();
    server.kill();
  }
}

async function waitForServer(origin) {
  for (let i = 0; i < 600; i++) {
    try {
      await fetch(`${origin}/api/me`);
      return;
    } catch {
      await new Promise((r) => setTimeout(r, 100));
    }
  }
  throw new Error("server did not start");
}

function signedInAs(page, name) {
  return page.waitForFunction(
    (n) => !document.getElementById("signed-in").hidden && document.getElementById("who").textContent === n,
    name,
    { timeout: 10000 },
  );
}

function signedOut(page) {
  return page.waitForFunction(() => !document.getElementById("signed-out").hidden, null, { timeout: 10000 });
}

async function signOut(page) {
  await page.click("#signout");
  await signedOut(page);
}

function statusContains(page, text) {
  return page.waitForFunction((t) => document.getElementById("status").textContent.includes(t), text, { timeout: 10000 });
}

async function serverUser(page, name) {
  const me = await page.evaluate(() => fetch("/api/me").then((r) => r.json()));
  if (me.username !== name) throw new Error(`server says signed in as ${JSON.stringify(me.username)}, want ${name}`);
}

async function passkeyCount(page, n) {
  const me = await page.evaluate(() => fetch("/api/me").then((r) => r.json()));
  if (me.passkeys !== n) throw new Error(`expected ${n} passkeys, server has ${me.passkeys}`);
}
