const KDF_ITERATIONS = 600_000;
const enc = new TextEncoder();
const dec = new TextDecoder();

const account = document.querySelector("#account");
const workspace = document.querySelector("#workspace");
const who = document.querySelector("#who");
const statusEl = document.querySelector("#status");
const recipients = [];

let session = loadSession();
let keys = null;

function loadSession() {
  try { return JSON.parse(sessionStorage.getItem("secureshare.session") || "null"); }
  catch { return null; }
}

function saveSession(value) {
  session = value;
  if (value) sessionStorage.setItem("secureshare.session", JSON.stringify(value));
  else sessionStorage.removeItem("secureshare.session");
}

function keyName(email) { return "secureshare.key." + email.trim().toLowerCase(); }

function setStatus(text, kind) {
  statusEl.textContent = text;
  statusEl.className = "status" + (kind ? " " + kind : "");
}

function bytesToB64(bytes) {
  let bin = "";
  for (let i = 0; i < bytes.length; i += 0x8000) {
    bin += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  }
  return btoa(bin);
}

function b64ToBytes(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function toHex(bytes) {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function fingerprint(spkiBytes) {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", spkiBytes));
  return [...digest.subarray(0, 16)].map((b) => b.toString(16).padStart(2, "0")).join(":");
}

async function api(path, options = {}) {
  const headers = new Headers(options.headers || {});
  if (session?.token) headers.set("Authorization", "Bearer " + session.token);
  if (options.json !== undefined) {
    headers.set("Content-Type", "application/json");
    options.body = JSON.stringify(options.json);
  }
  const response = await fetch(path, { ...options, headers });
  if (!response.ok) {
    let message = "The server answered HTTP " + response.status;
    try {
      const body = await response.json();
      if (body.message) message = body.message;
    } catch { /* empty or non-JSON */ }
    throw new Error(message);
  }
  if (response.status === 204) return null;
  const type = response.headers.get("content-type") || "";
  if (type.includes("application/json")) return response.json();
  return new Uint8Array(await response.arrayBuffer());
}

async function generateIdentity() {
  const oaep = await crypto.subtle.generateKey(
    { name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true,
    ["encrypt", "decrypt"]
  );
  const spki = new Uint8Array(await crypto.subtle.exportKey("spki", oaep.publicKey));
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", oaep.privateKey));
  return { spki, pkcs8 };
}

async function importIdentity(spki, pkcs8) {
  const oaepPrivate = await crypto.subtle.importKey(
    "pkcs8", pkcs8, { name: "RSA-OAEP", hash: "SHA-256" }, false, ["decrypt"]
  );
  const pssPrivate = await crypto.subtle.importKey(
    "pkcs8", pkcs8, { name: "RSA-PSS", hash: "SHA-256" }, false, ["sign"]
  );
  const oaepPublic = await crypto.subtle.importKey(
    "spki", spki, { name: "RSA-OAEP", hash: "SHA-256" }, false, ["encrypt"]
  );
  return { spki, oaepPrivate, pssPrivate, oaepPublic };
}

async function deriveAes(password, salt, usages) {
  const material = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: KDF_ITERATIONS, hash: "SHA-256" },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    usages
  );
}

async function protectPrivateKey(pkcs8, password, email) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const aes = await deriveAes(password, salt, ["encrypt"]);
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: enc.encode(email) }, aes, pkcs8
  ));
  return {
    kdf: "PBKDF2WithHmacSHA256",
    iterations: KDF_ITERATIONS,
    salt: bytesToB64(salt),
    iv: bytesToB64(iv),
    ciphertext: bytesToB64(ciphertext),
    publicKey: null
  };
}

async function unprotectPrivateKey(stored, password, email) {
  const aes = await deriveAes(password, b64ToBytes(stored.salt), ["decrypt"]);
  try {
    return new Uint8Array(await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: b64ToBytes(stored.iv), additionalData: enc.encode(email) },
      aes,
      b64ToBytes(stored.ciphertext)
    ));
  } catch {
    throw new Error("Wrong password, or this browser does not have that account's key.");
  }
}

async function showApp() {
  account.querySelector("#logout").hidden = false;
  workspace.hidden = false;
  who.hidden = false;
  who.textContent = session.fullName + " <" + session.email + ">";
  await refreshLists();
}

document.querySelector("#register-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const data = new FormData(event.target);
  const email = String(data.get("email")).trim().toLowerCase();
  const password = String(data.get("password"));
  const fullName = String(data.get("fullName")).trim();
  setStatus("Generating an RSA-2048 key and encrypting it with your password…");
  const identity = await generateIdentity();
  const stored = await protectPrivateKey(identity.pkcs8, password, email);
  stored.publicKey = bytesToB64(identity.spki);
  localStorage.setItem(keyName(email), JSON.stringify(stored));
  try {
    await api("/users/register", { method: "POST", json: { fullName, email, password, publicKey: stored.publicKey } });
    const login = await api("/users/login", { method: "POST", json: { email, password } });
    saveSession({ token: login.token, email, fullName: login.fullName, userId: login.userId });
    keys = await importIdentity(identity.spki, identity.pkcs8);
    identity.pkcs8.fill(0);
    setStatus("Registered. Public key fingerprint: " + await fingerprint(identity.spki), "ok");
    await showApp();
  } catch (error) {
    localStorage.removeItem(keyName(email));
    setStatus(error.message, "bad");
  }
});

document.querySelector("#login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const data = new FormData(event.target);
  const email = String(data.get("email")).trim().toLowerCase();
  const password = String(data.get("password"));
  const stored = JSON.parse(localStorage.getItem(keyName(email)) || "null");
  if (!stored) {
    setStatus("No private key for " + email + " in this browser. Register on this browser first.", "bad");
    return;
  }
  setStatus("Unlocking the private key…");
  try {
    const login = await api("/users/login", { method: "POST", json: { email, password } });
    const pkcs8 = await unprotectPrivateKey(stored, password, email);
    saveSession({ token: login.token, email, fullName: login.fullName, userId: login.userId });
    keys = await importIdentity(b64ToBytes(stored.publicKey), pkcs8);
    pkcs8.fill(0);
    setStatus("Logged in. Key fingerprint: " + await fingerprint(keys.spki), "ok");
    await showApp();
  } catch (error) {
    setStatus(error.message, "bad");
  }
});

document.querySelector("#logout").addEventListener("click", async () => {
  try { await api("/users/logout", { method: "POST" }); } catch { /* token may already be gone */ }
  saveSession(null);
  keys = null;
  workspace.hidden = true;
  who.hidden = true;
  who.textContent = "";
  document.querySelector("#logout").hidden = true;
  setStatus("Logged out.");
});

document.querySelector("#add-recipient").addEventListener("click", async () => {
  const input = document.querySelector("#recipient-email");
  const email = input.value.trim().toLowerCase();
  if (!email || recipients.some((r) => r.email === email)) return;
  try {
    const user = await api("/users/lookup?email=" + encodeURIComponent(email));
    const spki = b64ToBytes(user.publicKey);
    const oaepPublic = await crypto.subtle.importKey(
      "spki", spki, { name: "RSA-OAEP", hash: "SHA-256" }, false, ["encrypt"]
    );
    recipients.push({ email, oaepPublic, fingerprint: await fingerprint(spki) });
    input.value = "";
    renderRecipients();
  } catch (error) {
    setStatus(error.message, "bad");
  }
});

function renderRecipients() {
  const list = document.querySelector("#recipients");
  list.replaceChildren();
  for (const recipient of recipients) {
    const item = document.createElement("li");
    item.innerHTML = "<span></span><span class='fp'></span>";
    item.firstChild.textContent = recipient.email;
    item.lastChild.textContent = recipient.fingerprint;
    list.appendChild(item);
  }
}

document.querySelector("#send-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!keys) { setStatus("Unlock your key by logging in again.", "bad"); return; }
  const file = document.querySelector("#file").files[0];
  if (!file) return;
  setStatus("Encrypting " + file.name + "…");
  try {
    const plain = new Uint8Array(await file.arrayBuffer());
    const aes = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt"]);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv, tagLength: 128 }, aes, plain));
    const blob = new Uint8Array(iv.length + ciphertext.length);
    blob.set(iv, 0);
    blob.set(ciphertext, iv.length);
    const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", plain));
    const signature = new Uint8Array(await crypto.subtle.sign(
      { name: "RSA-PSS", saltLength: 32 }, keys.pssPrivate, hash
    ));
    const rawKey = new Uint8Array(await crypto.subtle.exportKey("raw", aes));
    const ownWrapped = new Uint8Array(await crypto.subtle.encrypt({ name: "RSA-OAEP" }, keys.oaepPublic, rawKey));

    const form = new FormData();
    form.set("file", new Blob([blob]), "blob.enc");
    form.set("fileName", file.name);
    form.set("sha256Hash", toHex(hash));
    form.set("signature", bytesToB64(signature));
    form.set("encryptedAesKey", bytesToB64(ownWrapped));
    const uploaded = await api("/files/upload", { method: "POST", body: form });

    if (recipients.length > 0) {
      const wrapped = [];
      for (const recipient of recipients) {
        const key = new Uint8Array(await crypto.subtle.encrypt({ name: "RSA-OAEP" }, recipient.oaepPublic, rawKey));
        wrapped.push({ email: recipient.email, wrappedKey: bytesToB64(key) });
      }
      await api("/files/" + uploaded.fileId + "/share", {
        method: "POST",
        json: { recipients: wrapped, permission: document.querySelector("#permission").value }
      });
    }
    rawKey.fill(0);
    setStatus("Encrypted and uploaded " + file.name + " (file id " + uploaded.fileId + ").", "ok");
    await refreshLists();
  } catch (error) {
    setStatus(error.message, "bad");
  }
});

async function refreshLists() {
  const shared = await api("/files/shared-with-me");
  const mine = await api("/files/mine");
  fillList(document.querySelector("#shared"), shared, true);
  fillList(document.querySelector("#mine"), mine, false);
}

function fillList(list, rows, shared) {
  list.replaceChildren();
  if (!rows.length) {
    const empty = document.createElement("li");
    empty.textContent = shared ? "Nothing shared with you." : "You have not uploaded any files.";
    list.appendChild(empty);
    return;
  }
  for (const row of rows) {
    const item = document.createElement("li");
    const label = document.createElement("span");
    label.textContent = row.fileName + (shared ? " from " + row.ownerName + " (" + row.permission + ")" : " (id " + row.fileId + ")");
    const open = document.createElement("button");
    open.type = "button";
    open.className = "secondary";
    open.textContent = "Open";
    open.addEventListener("click", () => openFile(row.fileId));
    item.append(label, open);
    list.appendChild(item);
  }
}

document.querySelector("#refresh").addEventListener("click", () => refreshLists().catch((error) => setStatus(error.message, "bad")));

async function openFile(fileId) {
  if (!keys) { setStatus("Unlock your key by logging in again.", "bad"); return; }
  let bundle;
  try {
    bundle = await api("/files/" + fileId + "/bundle");
  } catch (error) {
    setStatus(error.message, "bad");
    return;
  }
  if (bundle.permission === "VIEW") {
    setStatus("This file was shared with you as view-only; downloading is not permitted.", "bad");
    return;
  }
  const report = (outcome) => api("/files/" + fileId + "/receipt", { method: "POST", json: { outcome } }).catch(() => {});
  try {
    const blob = await api("/files/" + fileId + "/download");
    if (blob.length < 12 + 16) throw new Error("integrity");
    const iv = blob.subarray(0, 12);
    const ciphertext = blob.subarray(12);
    let rawKey;
    try {
      rawKey = new Uint8Array(await crypto.subtle.decrypt(
        { name: "RSA-OAEP" }, keys.oaepPrivate, b64ToBytes(bundle.wrappedKey)
      ));
    } catch {
      await report("FAILURE_KEY");
      setStatus("Access denied: your key cannot open this file. You are not an intended recipient.", "bad");
      return;
    }
    if (rawKey.length !== 32) {
      await report("FAILURE_KEY");
      setStatus("Access denied: your key cannot open this file. You are not an intended recipient.", "bad");
      return;
    }
    const aes = await crypto.subtle.importKey("raw", rawKey, { name: "AES-GCM" }, false, ["decrypt"]);
    rawKey.fill(0);
    let plain;
    try {
      plain = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv, tagLength: 128 }, aes, ciphertext));
    } catch {
      await report("FAILURE_INTEGRITY");
      setStatus("Integrity check FAILED: the encrypted file was modified or corrupted. Nothing was saved.", "bad");
      return;
    }
    const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", plain));
    const senderKey = await crypto.subtle.importKey(
      "spki", b64ToBytes(bundle.ownerPublicKey), { name: "RSA-PSS", hash: "SHA-256" }, false, ["verify"]
    );
    const signatureOk = toHex(hash) === bundle.sha256Hash && await crypto.subtle.verify(
      { name: "RSA-PSS", saltLength: 32 }, senderKey, b64ToBytes(bundle.signature), hash
    );
    if (!signatureOk) {
      await report("FAILURE_SIGNATURE");
      setStatus("Signature INVALID: this file is not authentically from " + bundle.ownerName
        + " <" + bundle.ownerEmail + ">. Treat it as untrusted. Nothing was saved.", "bad");
      return;
    }
    await report("SUCCESS");
    const url = URL.createObjectURL(new Blob([plain]));
    const link = document.createElement("a");
    link.href = url;
    link.download = bundle.fileName || "download.bin";
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    setStatus("Integrity verified. Signature valid (sender: " + bundle.ownerName + "). File saved to " + link.download + ".", "ok");
  } catch (error) {
    await report("FAILURE_INTEGRITY");
    setStatus(error.message === "integrity"
      ? "Integrity check FAILED: the encrypted file was modified or corrupted. Nothing was saved."
      : error.message, "bad");
  }
}

if (session?.token) {
  document.querySelector("#logout").hidden = false;
  who.hidden = false;
  who.textContent = session.fullName + " <" + session.email + "> — enter your password to unlock the key";
}
