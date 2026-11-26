// Passkeys Test web client. No dependencies.

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

let conditionalAbort = null;
let config = null;
const logEntries = []; // for export
const capabilities = {}; // for export
let lastUsedCredId = null;

// ---------- base64url ----------

function bufToB64u(buf) {
  const bytes = new Uint8Array(buf);
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function b64uToBuf(s) {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out.buffer;
}

const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");

// ---------- JSON <-> WebAuthn option conversion ----------

function parseCreationOptions(json) {
  if (PublicKeyCredential.parseCreationOptionsFromJSON) {
    try { return PublicKeyCredential.parseCreationOptionsFromJSON(json); } catch (e) { console.warn("native parse failed, using fallback", e); }
  }
  return {
    ...json,
    challenge: b64uToBuf(json.challenge),
    user: { ...json.user, id: b64uToBuf(json.user.id) },
    excludeCredentials: (json.excludeCredentials || []).map((c) => ({ ...c, id: b64uToBuf(c.id) })),
  };
}

function parseRequestOptions(json) {
  if (PublicKeyCredential.parseRequestOptionsFromJSON) {
    try { return PublicKeyCredential.parseRequestOptionsFromJSON(json); } catch (e) { console.warn("native parse failed, using fallback", e); }
  }
  return {
    ...json,
    challenge: b64uToBuf(json.challenge),
    allowCredentials: (json.allowCredentials || []).map((c) => ({ ...c, id: b64uToBuf(c.id) })),
    extensions: decodePRFInputs(json.extensions),
  };
}

function decodePRFInputs(ext) {
  const ev = ext?.prf?.eval;
  if (!ev) return ext;
  const out = { first: b64uToBuf(ev.first) };
  if (ev.second) out.second = b64uToBuf(ev.second);
  return { ...ext, prf: { ...ext.prf, eval: out } };
}

// credentialToJSON encodes a credential for the server. PRF outputs are
// secrets meant to stay on the client, so they're removed.
function credentialToJSON(cred) {
  const json = encodeCredential(cred);
  if (json.clientExtensionResults?.prf?.results) {
    json.clientExtensionResults = { ...json.clientExtensionResults, prf: { ...json.clientExtensionResults.prf } };
    delete json.clientExtensionResults.prf.results;
  }
  return json;
}

function encodeCredential(cred) {
  // Some password-manager extensions return objects without a working toJSON().
  try { if (typeof cred.toJSON === "function") return cred.toJSON(); } catch (e) { console.warn("toJSON failed", e); }
  const r = cred.response;
  const response = { clientDataJSON: bufToB64u(r.clientDataJSON) };
  if (r.attestationObject) {
    response.attestationObject = bufToB64u(r.attestationObject);
    response.transports = r.getTransports?.() ?? [];
  } else {
    response.authenticatorData = bufToB64u(r.authenticatorData);
    response.signature = bufToB64u(r.signature);
    if (r.userHandle) response.userHandle = bufToB64u(r.userHandle);
  }
  return {
    id: cred.id,
    rawId: bufToB64u(cred.rawId),
    type: cred.type,
    authenticatorAttachment: cred.authenticatorAttachment ?? undefined,
    response,
    clientExtensionResults: cred.getClientExtensionResults?.() ?? {},
  };
}

// ---------- decoding for the log ----------

function parseAuthData(buf) {
  if (!buf) return null;
  const v = new DataView(buf instanceof ArrayBuffer ? buf : buf.buffer);
  const flags = v.getUint8(32);
  const out = {
    rpIdHash: hex(buf.slice(0, 32)),
    flags: {
      raw: "0x" + flags.toString(16).padStart(2, "0"),
      UP_userPresent: !!(flags & 0x01),
      UV_userVerified: !!(flags & 0x04),
      BE_backupEligible: !!(flags & 0x08),
      BS_backedUp: !!(flags & 0x10),
      AT_attestedCredentialData: !!(flags & 0x40),
      ED_extensionData: !!(flags & 0x80),
    },
    signCount: v.getUint32(33),
  };
  if (flags & 0x40 && buf.byteLength >= 55) {
    const aaguid = hex(buf.slice(37, 53));
    out.aaguid = `${aaguid.slice(0, 8)}-${aaguid.slice(8, 12)}-${aaguid.slice(12, 16)}-${aaguid.slice(16, 20)}-${aaguid.slice(20)}`;
    out.credentialIdLength = v.getUint16(53);
  }
  return out;
}

function decodeCredential(cred) {
  const r = cred.response;
  const clientData = JSON.parse(new TextDecoder().decode(r.clientDataJSON));
  const out = {
    id: cred.id,
    type: cred.type,
    authenticatorAttachment: cred.authenticatorAttachment,
    clientData,
    clientExtensionResults: cred.getClientExtensionResults?.(),
  };
  if (r.attestationObject) {
    out.authenticatorData = parseAuthData(r.getAuthenticatorData?.());
    out.transports = r.getTransports?.();
    out.publicKeyAlgorithm = r.getPublicKeyAlgorithm?.();
  } else {
    out.authenticatorData = parseAuthData(r.authenticatorData);
    out.userHandle = r.userHandle ? bufToB64u(r.userHandle) : null;
  }
  return out;
}

// ---------- logging ----------

function log(kind, msg, data) {
  logEntries.push({
    time: new Date().toISOString(),
    kind,
    message: msg,
    data: data === undefined ? undefined : JSON.parse(JSON.stringify(data, binaryReplacer) ?? "null"),
  });
  const li = document.createElement("li");
  li.className = kind;
  const head = document.createElement("div");
  head.className = "entry-head";
  head.innerHTML = `<span class="time"></span><span class="msg"></span>`;
  $(".time", head).textContent = new Date().toLocaleTimeString();
  $(".msg", head).textContent = msg;
  li.append(head);
  if (data !== undefined) {
    const d = document.createElement("details");
    d.innerHTML = "<summary>details</summary><pre></pre>";
    $("pre", d).textContent = typeof data === "string" ? data : JSON.stringify(data, binaryReplacer, 2);
    li.append(d);
  }
  const ol = $("#log");
  $(".empty", ol)?.remove();
  ol.prepend(li);
}

// binaryReplacer shows ArrayBuffers and typed arrays as hex in JSON output.
function binaryReplacer(_key, value) {
  if (value instanceof ArrayBuffer) return `hex:${hex(value)}`;
  if (ArrayBuffer.isView(value)) return `hex:${hex(value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength))}`;
  return value;
}

function errorDetails(e) {
  return { name: e.name, message: e.message };
}

// Explanations for common DOMException names from navigator.credentials.
const ERROR_HINTS = {
  NotAllowedError: "Cancelled, timed out, or not allowed (no matching credential, or the user dismissed the prompt).",
  InvalidStateError: "The authenticator already holds a credential for this account (excludeCredentials matched).",
  SecurityError: "The RP ID is not valid for this origin, or the page is not a secure context.",
  NotSupportedError: "No authenticator supports the requested options.",
  AbortError: "The ceremony was aborted.",
};

// ---------- API ----------

async function api(method, path, body, query) {
  const url = path + (query ? "?" + new URLSearchParams(query) : "");
  const res = await fetch(url, {
    method,
    headers: body !== undefined ? { "Content-Type": "application/json" } : {},
    body: body !== undefined ? JSON.stringify(body) : undefined,
    credentials: "same-origin",
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw Object.assign(new Error(data.error || res.statusText), { server: true, status: res.status });
  return data;
}

// ---------- options editor ----------

// maybeEdit lets the user change the options JSON before the browser call.
// It returns the (possibly edited) JSON, or throws if the user cancels.
function maybeEdit(call, json) {
  if (!$("#edit-toggle").checked) return Promise.resolve(json);
  const dlg = $("#options-editor");
  const text = $("#editor-text");
  const err = $("#editor-error");
  const original = JSON.stringify(json, null, 2);
  $("#editor-call").textContent = call;
  text.value = original;
  err.hidden = true;
  $("#editor-reset").onclick = () => { text.value = original; err.hidden = true; };
  $("#editor-ok").onclick = (ev) => {
    try { JSON.parse(text.value); } catch (e) {
      ev.preventDefault();
      err.textContent = `Invalid JSON: ${e.message}`;
      err.hidden = false;
    }
  };
  dlg.showModal();
  text.focus();
  return new Promise((resolve, reject) => {
    dlg.addEventListener("close", () => {
      if (dlg.returnValue !== "ok") {
        log("err", "Ceremony cancelled in the options editor");
        reject(Object.assign(new Error("cancelled"), { logged: true }));
        return;
      }
      const edited = JSON.parse(text.value);
      if (text.value.trim() !== original.trim()) log("info", "Options edited before the browser call", edited);
      resolve(edited);
    }, { once: true });
  });
}

// ---------- ceremonies ----------

function readRegOptions(form) {
  const opts = $(".options", form);
  return {
    residentKey: $("[name=residentKey]", opts).value,
    userVerification: $("[name=userVerification]", opts).value,
    attachment: $("[name=attachment]", opts).value,
    attestation: $("[name=attestation]", opts).value,
    hints: $$("[name=hints]:checked", opts).map((c) => c.value),
    credProps: $("[name=credProps]", opts).checked,
    prf: $("[name=prf]", opts).checked,
    excludeExisting: $("[name=excludeExisting]", opts).checked,
  };
}

async function register(body, nickname) {
  await stopConditional();
  log("info", "Registration: requesting options", body);
  const options = await api("POST", "/api/register/begin", body);
  log("info", "Registration: server options (PublicKeyCredentialCreationOptionsJSON)", options);

  let cred;
  try {
    const publicKey = await maybeEdit("navigator.credentials.create()", options.publicKey);
    cred = await navigator.credentials.create({ publicKey: parseCreationOptions(publicKey) });
  } catch (e) {
    if (e.logged) throw e;
    log("err", `navigator.credentials.create() failed: ${e.name}: ${ERROR_HINTS[e.name] ?? e.message}`, errorDetails(e));
    throw Object.assign(e, { logged: true });
  }
  log("info", "Registration: authenticator response (decoded)", decodeCredential(cred));

  const result = await api("POST", "/api/register/finish", credentialToJSON(cred), nickname ? { nickname } : undefined);
  lastUsedCredId = result.credential.id;
  log("ok", `Registered passkey for "${result.user.name}"`, result.credential);
  return result;
}

function prfSalt() {
  return $("#prf-toggle").checked ? $("#signin-form").prfSalt.value : "";
}

async function login({ username, userVerification, hints }) {
  await stopConditional();
  const body = { username, userVerification, hints, prfSalt: prfSalt() };
  log("info", username ? `Sign-in: requesting options for "${username}"` : "Sign-in: requesting options (discoverable)", body);
  const options = await api("POST", "/api/login/begin", body);
  log("info", "Sign-in: server options (PublicKeyCredentialRequestOptionsJSON)", options);

  let cred;
  try {
    const publicKey = await maybeEdit("navigator.credentials.get()", options.publicKey);
    cred = await navigator.credentials.get({ publicKey: parseRequestOptions(publicKey) });
  } catch (e) {
    if (e.logged) throw e;
    log("err", `navigator.credentials.get() failed: ${e.name}: ${ERROR_HINTS[e.name] ?? e.message}`, errorDetails(e));
    throw Object.assign(e, { logged: true });
  }
  return finishLogin(cred);
}

async function finishLogin(cred) {
  log("info", "Sign-in: authenticator response (decoded)", decodeCredential(cred));
  let result;
  try {
    result = await api("POST", "/api/login/finish", credentialToJSON(cred));
  } catch (e) {
    if (/unknown credential/i.test(e.message) && PublicKeyCredential.signalUnknownCredential) {
      // Ask the credential manager to hide or remove a passkey the server no longer knows.
      const rpId = (await api("GET", "/api/config")).rpId;
      PublicKeyCredential.signalUnknownCredential({ rpId, credentialId: cred.id })
        .then(() => log("info", "Sent signalUnknownCredential for the rejected passkey", { id: cred.id }))
        .catch(() => {});
    }
    throw e;
  }
  lastUsedCredId = result.credential.id;
  log("ok", `Signed in as "${result.user.name}"`, result.credential);
  logPRF(cred);
  return result;
}

function logPRF(cred) {
  const prf = cred.getClientExtensionResults?.().prf;
  if (!prf) return;
  const first = prf.results?.first;
  if (first) {
    log("ok", `PRF output (${first.byteLength} bytes): ${hex(first)}`, {
      note: "Derived on the client and not sent to the server. The same passkey and salt always give the same output.",
      first: hex(first),
      second: prf.results.second ? hex(prf.results.second) : undefined,
    });
  } else {
    log("err", "PRF requested but no output came back. The authenticator may not support PRF, or (for security keys) the passkey was created without the prf extension.", prf);
  }
}

// Conditional mediation: passkeys show up in the username field's autofill.
async function startConditional() {
  if (!$("#conditional-toggle").checked) return;
  if (!(await PublicKeyCredential.isConditionalMediationAvailable?.())) return;
  await stopConditional();
  const ctrl = new AbortController();
  conditionalAbort = ctrl;
  try {
    const options = await api("POST", "/api/login/begin", { mediation: "conditional", prfSalt: prfSalt() });
    log("info", "Conditional UI armed: focus the username field to see passkeys in autofill", options);
    const cred = await navigator.credentials.get({
      publicKey: parseRequestOptions(options.publicKey),
      mediation: "conditional",
      signal: ctrl.signal,
    });
    conditionalAbort = null;
    const result = await finishLogin(cred);
    render(result.user);
  } catch (e) {
    // Superseded by an explicit ceremony: browsers reject the pending
    // conditional request with AbortError or NotAllowedError.
    if (e.name === "AbortError" || ctrl.signal.aborted || conditionalAbort !== ctrl && !e.server) return;
    log("err", `Conditional sign-in failed: ${e.message}`, errorDetails(e));
  }
}

async function stopConditional() {
  if (conditionalAbort) {
    conditionalAbort.abort();
    conditionalAbort = null;
    await new Promise((r) => setTimeout(r, 0));
  }
}

// ---------- rendering ----------

function fmtDate(s) {
  return s ? new Date(s).toLocaleString() : "never";
}

function render(user) {
  $("#signed-out").hidden = !!user;
  $("#signed-in").hidden = !user;
  if (!user) {
    $(".tabs button[data-tab=signin]").click();
    startConditional();
    return;
  }
  $("#user-name").textContent = user.displayName !== user.name ? `${user.displayName} (${user.name})` : user.name;
  $("#user-id").textContent = `user handle: ${user.id}`;
  const ul = $("#creds");
  ul.replaceChildren();
  if (!user.credentials.length) ul.innerHTML = '<li class="empty">No passkeys. You can only sign back in after adding one.</li>';
  for (const c of user.credentials) ul.append(renderCred(c));
}

function renderCred(c) {
  const li = document.createElement("li");
  li.className = "cred" + (c.id === lastUsedCredId ? " active" : "");
  li.innerHTML = `
    <div class="cred-top">
      <div class="cred-title"><span class="cred-name"></span> <span class="tags"></span></div>
      <div class="row">
        <button class="small-btn rename">Rename</button>
        <button class="small-btn danger delete">Delete</button>
      </div>
    </div>
    <div class="cred-id mono"></div>
    <dl></dl>`;
  $(".cred-name", li).textContent = c.nickname || c.aaguidName || "Unnamed passkey";
  $(".cred-id", li).textContent = c.id;
  const dark = matchMedia("(prefers-color-scheme: dark)").matches;
  const icon = (dark ? c.iconDark : c.iconLight) || c.iconLight || c.iconDark;
  if (icon) {
    const img = document.createElement("img");
    img.className = "cred-icon";
    img.alt = "";
    img.src = icon;
    $(".cred-title", li).prepend(img);
  }

  const tags = $(".tags", li);
  const tag = (text, cls = "") => {
    const t = document.createElement("span");
    t.className = "tag " + cls;
    t.textContent = text;
    tags.append(t);
  };
  if (c.id === lastUsedCredId) tag("this session", "on");
  if (c.flags.backupEligible) tag(c.flags.backupState ? "synced" : "backup eligible", "on");
  else tag("device-bound");
  if (c.flags.userVerified) tag("UV", "on");
  if (c.cloneWarning) tag("clone warning", "warn");

  const rows = [
    ["Authenticator", c.aaguidName ? `${c.aaguidName}` : "unknown"],
    ["AAGUID", c.aaguid],
    ["Attachment", c.attachment || "-"],
    ["Transports", (c.transports || []).join(", ") || "-"],
    ["Attestation", `${c.attestationFormat || "-"} / ${c.attestationType || "-"}`],
    ...(c.attestation && c.attestation.format !== "none"
      ? [["Statement", `${c.attestation.kind}${c.attestation.algorithm ? `, ${c.attestation.algorithm}` : ""}`]]
      : []),
    ["Sign count", String(c.signCount)],
    ["Created", fmtDate(c.createdAt)],
    ["Last used", `${fmtDate(c.lastUsedAt)} (${c.useCount}×)`],
  ];
  const dl = $("dl", li);
  for (const [k, v] of rows) {
    const dt = document.createElement("dt");
    const dd = document.createElement("dd");
    dt.textContent = k;
    dd.textContent = v;
    dl.append(dt, dd);
  }

  const certs = c.attestation?.certificates ?? [];
  if (certs.length) li.append(renderCerts(certs));

  $(".delete", li).onclick = async () => {
    if (!confirm(`Delete passkey "${$(".cred-name", li).textContent}" from the server?\n\nThe passkey stays on your authenticator; remove it there separately.`)) return;
    try {
      const r = await api("DELETE", `/api/credentials/${c.id}`);
      log("ok", "Deleted passkey on the server", { id: c.id });
      signalCredentials(r.user);
      render(r.user);
    } catch (e) { log("err", e.message); }
  };
  $(".rename", li).onclick = async () => {
    const name = prompt("Nickname for this passkey", c.nickname || "");
    if (name === null) return;
    try {
      const r = await api("PATCH", `/api/credentials/${c.id}`, { nickname: name });
      render(r.user);
    } catch (e) { log("err", e.message); }
  };
  return li;
}

function renderCerts(certs) {
  const d = document.createElement("details");
  d.className = "certs";
  d.innerHTML = `<summary>Attestation certificates (${certs.length})</summary>`;
  certs.forEach((cert, i) => {
    const box = document.createElement("div");
    box.className = "cert";
    const rows = [
      ["Subject", cert.subject],
      ["Issuer", cert.issuer],
      ["Valid", `${fmtDate(cert.notBefore)} to ${fmtDate(cert.notAfter)}`],
      ["Key / signature", `${cert.publicKeyAlgorithm} / ${cert.signatureAlgorithm}`],
      ["Serial", cert.serial],
      ["SHA-256", cert.sha256],
    ];
    if (cert.aaguid) rows.push(["AAGUID extension", cert.aaguid]);
    if (cert.isCA) rows.push(["CA", "yes"]);
    const title = document.createElement("div");
    title.className = "cert-title";
    title.textContent = i === 0 ? "Leaf (attestation) certificate" : `Chain certificate ${i}`;
    const dl = document.createElement("dl");
    for (const [k, v] of rows) {
      const dt = document.createElement("dt");
      const dd = document.createElement("dd");
      dt.textContent = k;
      dd.textContent = v;
      dl.append(dt, dd);
    }
    const pemD = document.createElement("details");
    pemD.innerHTML = "<summary>PEM</summary><pre></pre>";
    $("pre", pemD).textContent = cert.pem;
    box.append(title, dl, pemD);
    d.append(box);
  });
  return d;
}

// exportLog downloads the session (environment, capabilities, and every log
// entry) as JSON, for bug reports. PRF outputs are secrets, so they're removed.
function exportLog() {
  const report = {
    exportedAt: new Date().toISOString(),
    tool: "passkeys-test",
    page: location.origin,
    userAgent: navigator.userAgent,
    userAgentData: navigator.userAgentData ? { brands: navigator.userAgentData.brands, platform: navigator.userAgentData.platform, mobile: navigator.userAgentData.mobile } : undefined,
    server: config,
    capabilities,
    entries: logEntries.filter((e) => !e.message.startsWith("PRF output")),
  };
  const redactPRF = (k, v) => (k === "prf" && v?.results ? { ...v, results: "[redacted]" } : v);
  const blob = new Blob([JSON.stringify(report, redactPRF, 2)], { type: "application/json" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `passkeys-test-log-${report.exportedAt.replace(/[:.]/g, "-")}.json`;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}

// Signal API: tell the credential manager which passkeys are still valid.
async function signalCredentials(user) {
  if (!PublicKeyCredential.signalAllAcceptedCredentials) return;
  try {
    const rpId = (await api("GET", "/api/config")).rpId;
    await PublicKeyCredential.signalAllAcceptedCredentials({
      rpId,
      userId: user.id,
      allAcceptedCredentialIds: user.credentials.map((c) => c.id),
    });
    log("info", "Sent signalAllAcceptedCredentials to the credential manager");
  } catch (e) {
    log("err", `signalAllAcceptedCredentials failed: ${e.message}`);
  }
}

// Explanations for the (?) buttons in the capabilities card.
const CAP_HELP = {
  "Secure context":
    "WebAuthn only works on pages served over HTTPS or from http://localhost. On any other page, the browser hides the API completely.",
  WebAuthn:
    "Whether the browser has PublicKeyCredential, the API for creating and using passkeys. Every current browser has it; \"no\" means an old browser or a page that isn't a secure context.",
  "Platform authenticator (UVPAA)":
    "Whether this device has a built-in authenticator that can verify you, such as Touch ID, Windows Hello, or an Android screen lock. Sites check this to decide whether to offer \"create a passkey on this device\". It says nothing about security keys or phones.",
  "Conditional mediation":
    "Whether the browser can list passkeys in the autofill menu of a username field, so you can sign in without clicking a separate button. The \"Offer passkeys in username autofill\" option on the sign-in form uses this.",
  "parse*OptionsFromJSON":
    "Whether the browser can convert the server's JSON options into the binary form that navigator.credentials needs. Without it, this page converts the base64url fields itself. Either way, the result is the same.",
  "Signal API":
    "Whether the page can tell the passkey provider about changes on the server, so the provider can hide or update stale passkeys. This page sends a signal when you delete a passkey and when a sign-in fails because the server doesn't know the passkey. Security keys can't act on signals.",
  conditionalCreate:
    "Whether a password manager can create a passkey automatically, without a prompt, right after you sign in with a saved password. Sites use this to upgrade password accounts to passkeys.",
  conditionalGet:
    "The same as \"Conditional mediation\": passkeys can appear in the username field's autofill menu.",
  hybridTransport:
    "Whether you can sign in with a passkey on your phone by scanning a QR code. The phone and this device talk over Bluetooth to prove they're close together, so Bluetooth must be on.",
  passkeyPlatformAuthenticator:
    "Whether passkeys work here at all: through a built-in authenticator, or through a phone over the hybrid transport. Broader than userVerifyingPlatformAuthenticator.",
  userVerifyingPlatformAuthenticator:
    "The same as \"Platform authenticator (UVPAA)\": this device has a built-in authenticator that can verify you with a biometric or screen lock.",
  relatedOrigins:
    "Whether the browser supports Related Origin Requests: one RP ID shared by several domains that are listed in a /.well-known/webauthn file on the RP ID's domain. This server publishes that file.",
  immediateGet:
    "Whether the browser supports immediate sign-in requests, which show a prompt only when a matching passkey is already on hand and fail right away otherwise. Sites use them to fall back to another sign-in method without showing an empty dialog.",
  signalAllAcceptedCredentials:
    "Whether the page can send the full list of passkeys the server still accepts for an account. The provider can then hide the ones that aren't on the list. This page sends it after you delete a passkey.",
  signalCurrentUserDetails:
    "Whether the page can send an account's current username and display name, so the provider updates how its passkeys are labeled after a rename.",
  signalUnknownCredential:
    "Whether the page can report a single passkey that the server doesn't recognize. This page sends it when a sign-in fails with an unknown passkey, such as one whose account was deleted.",
};

const EXTENSION_HELP = {
  appid:
    "Lets security keys that were registered with the old U2F API sign in through WebAuthn. Only sites that used U2F need it.",
  appidExclude:
    "Stops a security key that's already registered through U2F from being registered again through WebAuthn.",
  credProps:
    "Reports after registration whether the new passkey is discoverable, meaning it's stored on the authenticator and can sign in without a username. This page requests it by default.",
  credProtect:
    "Lets the site ask a security key to release a passkey only after user verification, such as a PIN, so someone holding the key can't discover the account.",
  credentialProtectionPolicy:
    "The WebAuthn name for credProtect's input: which protection level the site asks the security key to apply to a new passkey.",
  enforceCredentialProtectionPolicy:
    "Tells the browser to fail registration if the authenticator can't apply the requested credProtect level, rather than creating a less protected passkey.",
  largeBlob:
    "Stores a small amount of data, such as a certificate, with a passkey on the authenticator, and reads it back at sign-in.",
  minPinLength:
    "Lets the site read the minimum PIN length that a security key enforces. Usually only for enterprise-approved sites.",
  prf:
    "Derives a secret from the passkey and a value the site chooses. The same passkey and value always give the same secret, which sites use as an encryption key. This page's \"Evaluate PRF\" option uses it.",
  hmacCreateSecret:
    "The security-key-level feature behind PRF: the key computes a secret from a value the site sends. Browsers usually expose it through the prf extension.",
  credBlob:
    "Stores a few bytes with a passkey on a security key when it's created.",
  getCredBlob: "Reads back the bytes stored with credBlob at sign-in.",
  payment:
    "Secure Payment Confirmation: uses a passkey to confirm a payment, with the browser showing the amount and merchant in a dialog the site can't change.",
};

function capHelp(key) {
  if (CAP_HELP[key]) return CAP_HELP[key];
  if (key.startsWith("extension:")) {
    const ext = key.slice("extension:".length);
    return EXTENSION_HELP[ext] ?? `Whether the browser supports the ${ext} WebAuthn extension.`;
  }
  return null;
}

let capHelpCount = 0;

async function renderCaps() {
  const dl = $("#caps");
  const add = (k, v) => {
    const dt = document.createElement("dt");
    const dd = document.createElement("dd");
    dt.append(k);
    capabilities[k] = v ?? null;
    if (typeof v === "boolean" || v === undefined) {
      dd.textContent = v === undefined ? "unknown" : v ? "yes" : "no";
      dd.className = v ? "yes" : "no";
    } else dd.textContent = v;
    dl.append(dt, dd);

    const text = capHelp(k);
    if (!text) return;
    const help = document.createElement("dd");
    help.className = "cap-help";
    help.id = `cap-help-${++capHelpCount}`;
    help.hidden = true;
    help.textContent = text;
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "help-btn";
    btn.textContent = "?";
    btn.setAttribute("aria-label", `What is ${k}?`);
    btn.setAttribute("aria-expanded", "false");
    btn.setAttribute("aria-controls", help.id);
    btn.addEventListener("click", () => toggleCapHelp(btn, help));
    dt.append(" ", btn);
    dl.append(help);
  };
  add("Secure context", window.isSecureContext);
  add("WebAuthn", !!window.PublicKeyCredential);
  if (!window.PublicKeyCredential) return;
  add("Platform authenticator (UVPAA)", await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable?.());
  add("Conditional mediation", await PublicKeyCredential.isConditionalMediationAvailable?.());
  add("parse*OptionsFromJSON", !!PublicKeyCredential.parseCreationOptionsFromJSON);
  add("Signal API", !!PublicKeyCredential.signalAllAcceptedCredentials);
  if (PublicKeyCredential.getClientCapabilities) {
    try {
      const caps = await PublicKeyCredential.getClientCapabilities();
      for (const [k, v] of Object.entries(caps).sort()) add(k, v);
    } catch (e) {
      add("getClientCapabilities", `error: ${e.message}`);
    }
  }
}

// Only one explanation is open at a time.
function toggleCapHelp(btn, help, open = help.hidden) {
  if (open) closeCapHelp();
  help.hidden = !open;
  btn.setAttribute("aria-expanded", String(open));
}

function closeCapHelp() {
  for (const b of $$('#caps .help-btn[aria-expanded="true"]')) {
    toggleCapHelp(b, document.getElementById(b.getAttribute("aria-controls")), false);
  }
}

document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeCapHelp(); });
document.addEventListener("click", (e) => { if (!e.target.closest("#caps")) closeCapHelp(); });

// ---------- passkey management pages ----------

// detectClient names the browser and OS, preferring User-Agent Client Hints,
// which (unlike the UA string) tell Chromium browsers apart.
function detectClient() {
  const ua = navigator.userAgent;
  const brands = (navigator.userAgentData?.brands ?? []).map((b) => b.brand);
  let browser = "other";
  if (brands.includes("Microsoft Edge") || /Edg(A|iOS)?\//.test(ua)) browser = "edge";
  else if (brands.includes("Brave") || navigator.brave) browser = "brave";
  else if (brands.includes("Opera") || /OPR\//.test(ua)) browser = "opera";
  else if (/Firefox\/|FxiOS\//.test(ua)) browser = "firefox";
  else if (brands.includes("Google Chrome")) browser = "chrome";
  else if (brands.includes("Chromium")) browser = "chromium";
  else if (/Chrome\/|CriOS\//.test(ua)) browser = "chrome";
  else if (/Safari\//.test(ua)) browser = "safari";

  const platform = navigator.userAgentData?.platform || ua;
  let os = "other";
  if (/Android/i.test(platform) || /Android/.test(ua)) os = "android";
  else if (/iPhone|iPad|iPod/.test(ua) || (/Macintosh/.test(ua) && navigator.maxTouchPoints > 1)) os = "ios";
  else if (/Win/i.test(platform)) os = "windows";
  else if (/Mac/i.test(platform)) os = "macos";
  else if (/Linux|CrOS/i.test(platform)) os = /CrOS/.test(ua) || platform === "Chrome OS" ? "chromeos" : "linux";
  return { browser, os };
}

const BROWSER_NAMES = {
  chrome: "Chrome", chromium: "Chromium", edge: "Edge", brave: "Brave", opera: "Opera",
  firefox: "Firefox", safari: "Safari", other: "your browser",
};
const OS_NAMES = {
  windows: "Windows", macos: "macOS", linux: "Linux", chromeos: "ChromeOS",
  android: "Android", ios: "iOS or iPadOS", other: "your system",
};

// managementPages lists where passkeys can be viewed or deleted. Entries with
// a url that pages may open get an Open link; internal pages (chrome://,
// about:) can only be copied, because browsers block links to them.
function managementPages({ browser, os }) {
  const out = [];
  const chromium = (scheme, name) => {
    out.push({
      label: `${name} Password Manager`,
      detail: "Passkeys that this browser saved and syncs, listed with your passwords.",
      url: `${scheme}://password-manager/passwords`,
    });
    out.push({
      label: "Security keys",
      detail: "Set or change a security key's PIN, list and delete the passkeys stored on it, or reset it.",
      url: `${scheme}://settings/securityKeys`,
    });
  };
  if (os === "ios") {
    out.push({
      label: "Passwords app",
      detail: "Passkeys saved in iCloud Keychain. Other passkey providers are under Settings > General > AutoFill & Passwords.",
    });
  } else {
    switch (browser) {
      case "chrome":
        if (os === "android") break;
        chromium("chrome", "Google");
        break;
      case "chromium":
        chromium("chrome", "Chromium");
        break;
      case "brave":
        chromium("brave", "Brave");
        break;
      case "opera":
        chromium("opera", "Opera");
        break;
      case "edge":
        out.push({
          label: "Edge passwords",
          detail: "Passkeys that Edge saved and syncs, listed with your passwords.",
          url: "edge://wallet/passwords",
        });
        break;
      case "firefox":
        out.push({
          label: "Security keys",
          detail: "Set or change a security key's PIN, list and delete the passkeys stored on it, or reset it. Firefox stores no passkeys itself; it uses the system's store or a security key.",
          url: "about:webauthn",
        });
        break;
      case "safari":
        out.push({
          label: "Passwords app",
          detail: "Safari saves passkeys in iCloud Keychain. Safari has no page for managing security keys.",
        });
        break;
    }
  }
  switch (os) {
    case "windows":
      out.push({
        label: "Windows passkeys",
        detail: "Passkeys saved with Windows Hello on this device. In Settings: Accounts > Passkeys.",
        url: "ms-settings:savedpasskeys",
        open: true,
      });
      out.push({
        label: "Windows security key settings",
        detail: "Reset a security key or change its PIN. In Settings: Accounts > Sign-in options > Security key.",
      });
      break;
    case "macos":
      if (browser !== "safari") {
        out.push({
          label: "Passwords app",
          detail: "Passkeys saved in iCloud Keychain, which Chrome, Edge, and Firefox can also use on macOS.",
        });
      }
      break;
    case "android":
      out.push({
        label: "Google Password Manager",
        detail: "Passkeys saved to your Google account, synced to your Android devices and Chrome. On the device: Settings > Passwords & accounts.",
        url: "https://passwords.google.com/",
        open: true,
      });
      break;
    case "linux":
      out.push({
        label: "This tool's key command",
        detail: "Lists, deletes, and resets passkeys on a USB security key from the terminal.",
        url: "./passkeys-test key ls",
      });
      break;
  }
  out.push({
    label: "Password manager extensions",
    detail: "Passkeys saved by an extension such as Bitwarden or 1Password are only visible in that extension's vault. The provider name in each passkey's details tells you where it lives.",
  });
  return out;
}

function renderManagement() {
  const client = detectClient();
  const intro = $("#manage-intro");
  intro.textContent = `Detected ${BROWSER_NAMES[client.browser]} on ${OS_NAMES[client.os]}. Deleting a passkey here doesn't remove it from where it's stored; use these pages for that. Browsers block links to their internal pages, so copy the address into the address bar.`;
  const ul = $("#manage");
  for (const p of managementPages(client)) {
    const li = document.createElement("li");
    const head = document.createElement("div");
    head.className = "manage-head";
    const title = document.createElement("strong");
    title.textContent = p.label;
    head.append(title);
    if (p.url) {
      const code = document.createElement("code");
      code.textContent = p.url;
      head.append(code);
      if (p.open) {
        const a = document.createElement("a");
        a.href = p.url;
        a.textContent = "Open";
        a.className = "small-link";
        if (p.url.startsWith("http")) { a.target = "_blank"; a.rel = "noopener"; }
        head.append(a);
      }
      const copy = document.createElement("button");
      copy.type = "button";
      copy.className = "small-btn";
      copy.textContent = "Copy";
      copy.addEventListener("click", async () => {
        try {
          await navigator.clipboard.writeText(p.url);
          copy.textContent = "Copied";
        } catch {
          copy.textContent = "Copy failed";
        }
        setTimeout(() => (copy.textContent = "Copy"), 1500);
      });
      head.append(copy);
    }
    const detail = document.createElement("div");
    detail.className = "muted small";
    detail.textContent = p.detail;
    li.append(head, detail);
    ul.append(li);
  }
}

// ---------- wiring ----------

function withBusy(btn, fn) {
  return async (ev) => {
    ev.preventDefault();
    btn.disabled = true;
    try { await fn(); } catch (e) { if (!e.logged) log("err", e.message, e.server ? undefined : errorDetails(e)); }
    finally { btn.disabled = false; }
  };
}

async function init() {
  const tpl = $("#reg-options-tpl");
  for (const slot of $$(".reg-options")) slot.replaceWith(tpl.content.cloneNode(true));

  const cfg = (config = await api("GET", "/api/config"));
  $("#rp-info").innerHTML = `RP ID <code></code> · origin <code></code>`;
  const codes = $$("#rp-info code");
  codes[0].textContent = cfg.rpId;
  codes[1].textContent = cfg.origins.join(", ");

  const banner = $("#banner");
  if (!window.isSecureContext || !window.PublicKeyCredential) {
    banner.hidden = false;
    banner.textContent = "WebAuthn is unavailable: this page is not a secure context. Use http://localhost or HTTPS.";
  } else if (!cfg.origins.includes(location.origin)) {
    banner.hidden = false;
    banner.textContent = `This page's origin (${location.origin}) is not in the server's allowed origins (${cfg.origins.join(", ")}). Ceremonies will fail. Restart the server with -origin ${location.origin}.`;
  }

  $$(".tabs button").forEach((b) => {
    b.onclick = () => {
      $$(".tabs button").forEach((x) => x.setAttribute("aria-selected", x === b));
      $$("[data-panel]").forEach((p) => (p.hidden = p.dataset.panel !== b.dataset.tab));
    };
  });

  const signin = $("#signin-form");
  signin.onsubmit = withBusy($("button[type=submit]", signin), async () => {
    try {
      const r = await login({
        username: signin.username.value.trim(),
        userVerification: signin.userVerification.value,
        hints: $$("[name=hints]:checked", signin).map((c) => c.value),
      });
      render(r.user);
    } catch (e) {
      startConditional();
      throw e;
    }
  });
  $("#prf-toggle").onchange = (e) => {
    $("#prf-salt-label").hidden = !e.target.checked;
    startConditional();
  };
  $("#signin-form").prfSalt.onchange = () => startConditional();
  $("#conditional-toggle").onchange = (e) => (e.target.checked ? startConditional() : stopConditional());

  const reg = $("#register-form");
  reg.onsubmit = withBusy($("button[type=submit]", reg), async () => {
    try {
      const r = await register({ username: reg.username.value.trim(), displayName: reg.displayName.value.trim(), ...readRegOptions(reg) });
      render(r.user);
    } catch (e) {
      startConditional();
      throw e;
    }
  });

  const add = $("#add-form");
  add.onsubmit = withBusy($("button[type=submit]", add), async () => {
    const r = await register(readRegOptions(add), add.nickname.value.trim());
    add.nickname.value = "";
    render(r.user);
  });

  $("#logout").onclick = async () => {
    await api("POST", "/api/logout");
    lastUsedCredId = null;
    log("info", "Signed out");
    render(null);
  };
  $("#delete-account").onclick = async () => {
    if (!confirm("Delete this account and all its passkeys from the server?")) return;
    const me = (await api("GET", "/api/me")).user;
    await api("DELETE", "/api/me");
    log("ok", "Account deleted");
    if (me && PublicKeyCredential.signalUnknownCredential) {
      for (const c of me.credentials) {
        try { await PublicKeyCredential.signalUnknownCredential({ rpId: cfg.rpId, credentialId: c.id }); } catch {}
      }
      log("info", "Sent signalUnknownCredential for the deleted passkeys");
    }
    render(null);
  };
  $("#clear-log").onclick = () => {
    logEntries.length = 0;
    $("#log").innerHTML = '<li class="empty">Log cleared.</li>';
  };
  $("#export-log").onclick = exportLog;
  $("#log").innerHTML = '<li class="empty">Register or sign in to see each WebAuthn ceremony step.</li>';

  renderCaps();
  renderManagement();
  const me = await api("GET", "/api/me");
  render(me.user);
}

init().catch((e) => log("err", `Init failed: ${e.message}`));
