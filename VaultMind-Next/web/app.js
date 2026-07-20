const connectDialog = document.querySelector("#connect-dialog");
const unlockDialog = document.querySelector("#unlock-dialog");
const credentialDialog = document.querySelector("#credential-dialog");
const tokenInput = document.querySelector("#token-input");
let apiToken = "";
let isAuthenticated = false;
let ownerExists = false;
let vaultKey = null;
let vaultKeyBytes = null;
let vaultItemSalt = null;
let vaultLockTimer = null;
const VAULT_IDLE_MILLISECONDS = 5 * 60 * 1000;

async function api(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${apiToken}`,
      ...(options.headers || {}),
    },
  });
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    const error = new Error(body.detail || `API returned ${response.status}`);
    error.status = response.status;
    throw error;
  }
  return response.status === 204 ? null : response.json();
}

function base64urlToBytes(value) {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  return base64ToBytes(base64.padEnd(Math.ceil(base64.length / 4) * 4, "="));
}

function bytesToBase64url(value) {
  return bytesToBase64(new Uint8Array(value))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function decodePasskeyOptions(options) {
  options.challenge = base64urlToBytes(options.challenge);
  if (options.user) options.user.id = base64urlToBytes(options.user.id);
  for (const credential of options.excludeCredentials || []) {
    credential.id = base64urlToBytes(credential.id);
  }
  for (const credential of options.allowCredentials || []) {
    credential.id = base64urlToBytes(credential.id);
  }
  return options;
}

function serializePasskey(credential) {
  const response = {
    clientDataJSON: bytesToBase64url(credential.response.clientDataJSON),
  };
  if (credential.response.attestationObject) {
    response.attestationObject = bytesToBase64url(credential.response.attestationObject);
    response.transports = credential.response.getTransports?.() || [];
  } else {
    response.authenticatorData = bytesToBase64url(credential.response.authenticatorData);
    response.signature = bytesToBase64url(credential.response.signature);
    response.userHandle = credential.response.userHandle
      ? bytesToBase64url(credential.response.userHandle) : null;
  }
  return {
    id: credential.id,
    rawId: bytesToBase64url(credential.rawId),
    response,
    type: credential.type,
    authenticatorAttachment: credential.authenticatorAttachment,
    clientExtensionResults: credential.getClientExtensionResults(),
  };
}

async function refreshAuthState() {
  const statusPill = document.querySelector("#api-state");
  const connectButton = document.querySelector("#connect-button");
  try {
    const status = await api("/api/v1/auth/status");
    isAuthenticated = status.authenticated;
    ownerExists = status.owner_exists;
    if (!isAuthenticated) lockVault();
    document.querySelector("#owner-setup-fields").hidden = ownerExists;
    document.querySelector("#setup-passkey").hidden = ownerExists;
    document.querySelector("#sign-in-passkey").hidden = !ownerExists;
    document.querySelector("#auth-dialog-copy").textContent = ownerExists
      ? "Use your device passkey. No vault password or server token is transmitted."
      : "Create the owner passkey using the one-time deployment bootstrap token.";
    statusPill.textContent = isAuthenticated ? "Passkey session" : "Signed out";
    statusPill.className = `pill ${isAuthenticated ? "online" : "offline"}`;
    connectButton.textContent = isAuthenticated ? "Sign out" : "Sign in";
    const securityState = document.querySelector("#security-state");
    const securityMessage = document.querySelector("#security-message");
    const protectionState = document.querySelector("#protection-state");
    if (!ownerExists) {
      securityState.textContent = "Setup";
      securityMessage.textContent = "Create the owner passkey before storing credentials.";
      protectionState.textContent = "Waiting";
    } else if (!isAuthenticated) {
      securityState.textContent = "Locked";
      securityMessage.textContent = "Your encrypted workspace is locked behind its passkey.";
      protectionState.textContent = "Locked";
    } else {
      securityState.textContent = "Active";
      securityMessage.textContent = "Passkey authentication and client-side encryption are active.";
      protectionState.textContent = "Protected";
    }
    if (isAuthenticated) {
      const initialView = location.hash === "#connections" ? "connections" : "overview";
      await activateView(initialView);
      if (new URLSearchParams(location.search).has("email_connected")) {
        history.replaceState({}, "", `${location.pathname}#connections`);
      }
    }
  } catch {
    isAuthenticated = false;
    statusPill.textContent = "Unavailable";
    statusPill.className = "pill offline";
  }
}

document.querySelector("#auth-form").addEventListener("submit", async event => {
  event.preventDefault();
  const error = document.querySelector("#auth-error");
  error.textContent = "";
  if (!window.PublicKeyCredential) {
    error.textContent = "This browser does not support passkeys.";
    return;
  }
  try {
    if (!ownerExists) {
      apiToken = tokenInput.value;
      const start = await api("/api/v1/auth/register/options", {
        method: "POST",
        body: JSON.stringify({
          email_address: document.querySelector("#owner-email").value,
          display_name: document.querySelector("#owner-name").value,
        }),
      });
      const credential = await navigator.credentials.create({
        publicKey: decodePasskeyOptions(start.public_key),
      });
      await api("/api/v1/auth/register/finish", {
        method: "POST",
        body: JSON.stringify({
          ceremony_id: start.ceremony_id,
          credential: serializePasskey(credential),
        }),
      });
      apiToken = "";
      tokenInput.value = "";
    } else {
      const start = await api("/api/v1/auth/login/options", { method: "POST" });
      const credential = await navigator.credentials.get({
        publicKey: decodePasskeyOptions(start.public_key),
      });
      await api("/api/v1/auth/login/finish", {
        method: "POST",
        body: JSON.stringify({
          ceremony_id: start.ceremony_id,
          credential: serializePasskey(credential),
        }),
      });
    }
    connectDialog.close();
    await refreshAuthState();
  } catch (caught) {
    apiToken = "";
    error.textContent = caught.name === "NotAllowedError"
      ? "Passkey verification was canceled or timed out."
      : caught.message;
  }
});

function bytesToBase64(bytes) {
  let binary = "";
  bytes.forEach(byte => { binary += String.fromCharCode(byte); });
  return btoa(binary);
}

function base64ToBytes(value) {
  return Uint8Array.from(atob(value), character => character.charCodeAt(0));
}

async function deriveVaultKeyBytes(passphrase, salt, iterations = 600000) {
  const material = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(passphrase), "PBKDF2", false, ["deriveBits"]
  );
  return new Uint8Array(await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations }, material, 256
  ));
}

async function importVaultKey(bytes) {
  return crypto.subtle.importKey(
    "raw", bytes, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]
  );
}

async function encryptWithKey(key, value) {
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = new TextEncoder().encode(JSON.stringify(value));
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, key, plaintext);
  return {
    nonce: bytesToBase64(nonce),
    ciphertext: bytesToBase64(new Uint8Array(ciphertext)),
  };
}

async function decryptWithKey(key, nonce, ciphertext) {
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: base64ToBytes(nonce) }, key,
    base64ToBytes(ciphertext)
  );
  return JSON.parse(new TextDecoder().decode(plaintext));
}

async function createKeyEnvelope(passphrase, keyBytes) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const wrappingBytes = await deriveVaultKeyBytes(passphrase, salt);
  const wrappingKey = await importVaultKey(wrappingBytes);
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const wrapped = await crypto.subtle.encrypt({
    name: "AES-GCM", iv: nonce,
    additionalData: new TextEncoder().encode("vaultmind-vault-key-v1"),
  }, wrappingKey, keyBytes);
  wrappingBytes.fill(0);
  return {
    kdf: "pbkdf2-sha256", iterations: 600000,
    salt: bytesToBase64(salt), nonce: bytesToBase64(nonce),
    wrapped_key: bytesToBase64(new Uint8Array(wrapped)), key_version: 2,
  };
}

async function openKeyEnvelope(passphrase, envelope) {
  if (envelope.kdf !== "pbkdf2-sha256") throw new Error("Unsupported vault KDF");
  const wrappingBytes = await deriveVaultKeyBytes(
    passphrase, base64ToBytes(envelope.salt), envelope.iterations
  );
  const wrappingKey = await importVaultKey(wrappingBytes);
  try {
    return new Uint8Array(await crypto.subtle.decrypt({
      name: "AES-GCM", iv: base64ToBytes(envelope.nonce),
      additionalData: new TextEncoder().encode("vaultmind-vault-key-v1"),
    }, wrappingKey, base64ToBytes(envelope.wrapped_key)));
  } finally {
    wrappingBytes.fill(0);
  }
}

async function getKeyEnvelope() {
  try {
    return await api("/api/v1/vault/key-envelope");
  } catch (error) {
    if (error.status === 404) return null;
    throw error;
  }
}

async function unlockVault(passphrase) {
  if (!isAuthenticated) throw new Error("Sign in before unlocking the vault");
  const [existingItems, storedEnvelope] = await Promise.all([
    api("/api/v1/vault/items"), getKeyEnvelope(),
  ]);
  let keyBytes;
  let keyEnvelope = storedEnvelope;
  if (keyEnvelope) {
    keyBytes = await openKeyEnvelope(passphrase, keyEnvelope);
  } else if (existingItems.length) {
    const first = existingItems[0];
    keyBytes = await deriveVaultKeyBytes(passphrase, base64ToBytes(first.kdf_salt));
    const legacyKey = await importVaultKey(keyBytes);
    await decryptWithKey(legacyKey, first.nonce, first.ciphertext);
    keyEnvelope = await api("/api/v1/vault/key-envelope", {
      method: "PUT", body: JSON.stringify(await createKeyEnvelope(passphrase, keyBytes)),
    });
  } else {
    keyBytes = crypto.getRandomValues(new Uint8Array(32));
    keyEnvelope = await api("/api/v1/vault/key-envelope", {
      method: "PUT", body: JSON.stringify(await createKeyEnvelope(passphrase, keyBytes)),
    });
  }
  if (keyBytes.length !== 32) throw new Error("Vault key has an invalid size");
  if (vaultKeyBytes) vaultKeyBytes.fill(0);
  vaultKeyBytes = keyBytes;
  vaultKey = await importVaultKey(keyBytes);
  vaultItemSalt = existingItems[0]?.kdf_salt || keyEnvelope.salt;
  localStorage.removeItem("vaultmind-vault-salt");
  localStorage.removeItem("vaultmind-vault-verifier");
  scheduleVaultLock();
  updateVaultLockUi();
}

function updateVaultLockUi() {
  const state = document.querySelector("#vault-lock-state");
  const button = document.querySelector("#unlock-button");
  const unlocked = Boolean(vaultKey);
  state.textContent = unlocked ? "Unlocked locally" : "Locked";
  state.className = `pill ${unlocked ? "online" : "offline"}`;
  button.textContent = unlocked ? "Lock now" : "Unlock locally";
}

function lockVault() {
  if (vaultLockTimer) clearTimeout(vaultLockTimer);
  vaultLockTimer = null;
  if (vaultKeyBytes) vaultKeyBytes.fill(0);
  vaultKeyBytes = null;
  vaultKey = null;
  vaultItemSalt = null;
  document.querySelector("#passphrase-input").value = "";
  document.querySelector("#current-passphrase").value = "";
  document.querySelector("#new-passphrase").value = "";
  document.querySelector("#confirm-passphrase").value = "";
  const vaultList = document.querySelector("#vault-list");
  vaultList.className = "empty-state";
  vaultList.textContent = "Vault locked. Unlock locally to view credentials.";
  updateVaultLockUi();
}

function scheduleVaultLock() {
  if (!vaultKey) return;
  if (vaultLockTimer) clearTimeout(vaultLockTimer);
  vaultLockTimer = setTimeout(async () => {
    lockVault();
    if (document.querySelector("#vault").classList.contains("active-view")) {
      await loadVault();
    }
  }, VAULT_IDLE_MILLISECONDS);
}

async function refreshOverview() {
  const state = document.querySelector("#api-state");
  try {
    const [summary, jobs] = await Promise.all([
      api("/api/v1/dashboard"), api("/api/v1/rotation/jobs"),
    ]);
    document.querySelector("#vault-items").textContent = summary.vault_items;
    document.querySelector("#active-policies").textContent = summary.active_policies;
    document.querySelector("#rotations-due").textContent = summary.rotations_due;
    document.querySelector("#needs-approval").textContent = summary.jobs_needing_approval;
    state.textContent = "Connected";
    state.className = "pill online";
    renderJobs(document.querySelector("#job-list"), jobs);
  } catch {
    state.textContent = "Disconnected";
    state.className = "pill offline";
    if (!connectDialog.open) connectDialog.showModal();
  }
}

function renderJobs(container, jobs) {
  if (!jobs.length) {
    container.className = "empty-state";
    container.textContent = "No rotations are waiting. Your queue is clear.";
    return;
  }
  container.className = "";
  container.innerHTML = jobs.slice(0, 8).map(job => `
    <div class="job"><div><strong>${escapeText(job.provider_id)}</strong><br>
    <small>${escapeText(job.status)} · ${new Date(job.due_at).toLocaleDateString()}</small></div>
    <span class="pill ${job.status === "proposed" ? "offline" : "online"}">${escapeText(job.status)}</span></div>
  `).join("");
}

async function loadVault() {
  const container = document.querySelector("#vault-list");
  try {
    const items = await api("/api/v1/vault/items");
    if (!items.length) {
      container.className = "empty-state";
      container.textContent = "Your vault is empty. Add your first credential.";
      return;
    }
    const records = await Promise.all(items.map(async item => {
      if (!vaultKey) return { item, data: null };
      try {
        return { item, data: await decryptWithKey(vaultKey, item.nonce, item.ciphertext) };
      } catch {
        return { item, data: null };
      }
    }));
    container.className = "";
    container.innerHTML = records.map(({ item, data }) => `
      <div class="vault-row"><div><strong>${escapeText(data?.title || "Encrypted item")}</strong>
      <small>${escapeText(data?.username || "Unlock locally to view")}</small></div>
      <span class="site">${escapeText(item.site_origin)}</span>
      <span class="site">${new Date(item.updated_at).toLocaleDateString()}</span>
      <span class="lock-label">${data ? "UNLOCKED" : "ENCRYPTED"}</span></div>
    `).join("");
  } catch (error) {
    showError(container, error.message);
  }
}

async function loadRotations() {
  const policyList = document.querySelector("#policy-list");
  const grantList = document.querySelector("#grant-list");
  try {
    const [policies, grants] = await Promise.all([
      api("/api/v1/rotation/policies"), api("/api/v1/automation/grants"),
    ]);
    policyList.className = policies.length ? "" : "empty-state";
    policyList.innerHTML = policies.length ? policies.map(policy => `
      <div class="job"><div><strong>${policy.interval_days}-day rotation</strong><br>
      <small>${escapeText(policy.approval_mode)} · next ${new Date(policy.next_due_at).toLocaleDateString()}</small></div>
      <span class="pill ${policy.enabled ? "online" : "offline"}">${policy.enabled ? "active" : "paused"}</span></div>
    `).join("") : "No rotation policies yet.";
    grantList.className = grants.length ? "" : "empty-state";
    grantList.innerHTML = grants.length ? grants.map(grant => `
      <div class="job"><div><strong>${escapeText(grant.agent_id)}</strong><br>
      <small>expires ${new Date(grant.expires_at).toLocaleDateString()}</small></div><span class="pill online">scoped</span></div>
    `).join("") : "Automatic rotations require an item-scoped trusted-agent grant.";
  } catch (error) {
    showError(policyList, error.message);
  }
}

async function loadConnections() {
  const container = document.querySelector("#provider-list");
  const eventList = document.querySelector("#email-event-list");
  try {
    const [providers, connections, events, recommendations] = await Promise.all([
      api("/api/v1/email/providers"), api("/api/v1/email/connections"),
      api("/api/v1/email/security-events"), api("/api/v1/ai/recommendations"),
    ]);
    container.innerHTML = providers.map(provider => {
      const connection = connections.find(row => row.provider === provider.provider);
      const active = connection?.status === "active";
      const label = provider.provider === "google" ? "Google" : "Microsoft";
      return `
      <article class="provider-card"><div class="provider-icon">${provider.provider === "google" ? "G" : "M"}</div>
      <h2>${label}</h2>
      <p class="section-copy">Metadata-only security monitoring with OAuth and PKCE.</p>
      ${connection ? `<p class="connection-state"><strong>${escapeText(connection.email_address)}</strong><br>
        <span class="pill ${active ? "online" : "offline"}">${escapeText(connection.status)}</span></p>` : ""}
      <ul class="scope-list">${provider.scopes.map(scope => `<li>${escapeText(scope)}</li>`).join("")}</ul>
      <div class="connection-actions"><button class="secondary oauth-connect" data-provider="${provider.provider}"
        ${provider.configured ? "" : "disabled"}>${provider.configured ? (active ? `Reconnect ${label}` : `Connect ${label}`) : "OAuth setup required"}</button>
      ${active ? `<button class="danger oauth-revoke" data-provider="${provider.provider}">Revoke</button>` : ""}</div></article>`;
    }).join("");
    eventList.className = events.length ? "" : "empty-state";
    eventList.innerHTML = events.length ? events.map(event => {
      const plan = recommendations.find(value => value.event_id === event.event_id);
      return `
      <div class="job"><div><strong>${escapeText(event.category.replaceAll("_", " "))}</strong><br>
      <small>${escapeText(event.provider)} · ${escapeText(event.source_domain)}${plan ? ` · AI: ${escapeText(plan.action.replaceAll("_", " "))}` : ""}</small></div>
      <span class="site">${new Date(event.occurred_at).toLocaleString()}</span></div>`;
    }).join("") : "No classified security notifications yet.";
  } catch (error) {
    showError(container, error.message);
  }
}

document.querySelector("#provider-list").addEventListener("click", async event => {
  const button = event.target.closest("button[data-provider]");
  if (!button) return;
  button.disabled = true;
  try {
    if (button.classList.contains("oauth-connect")) {
      const result = await api(
        `/api/v1/email/connections/${button.dataset.provider}/start`, { method: "POST" }
      );
      window.location.assign(result.authorization_url);
      return;
    }
    if (button.classList.contains("oauth-revoke") &&
        window.confirm("Revoke this email connection and erase its stored tokens?")) {
      await api(`/api/v1/email/connections/${button.dataset.provider}`, { method: "DELETE" });
      await loadConnections();
    }
  } catch (error) {
    showError(document.querySelector("#provider-list"), error.message);
  } finally {
    button.disabled = false;
  }
});

async function loadSecurity() {
  const devices = document.querySelector("#device-list");
  const readiness = document.querySelector("#backend-readiness");
  try {
    const rows = await api("/api/v1/devices");
    devices.className = rows.length ? "" : "empty-state";
    devices.innerHTML = rows.length ? rows.map(device => `
      <div class="job"><div><strong>${escapeText(device.display_name)}</strong><br>
      <small>${escapeText(device.platform)} · last seen ${new Date(device.last_seen_at).toLocaleString()}</small></div>
      <div class="header-actions"><span class="pill ${device.status === "active" ? "online" : "offline"}">${escapeText(device.status)}</span>
      ${device.status === "active" ? `<button class="danger revoke-device" data-device-id="${escapeText(device.device_id)}">Revoke</button>` : ""}</div></div>
    `).join("") : "No trusted agents registered.";
  } catch (error) {
    showError(devices, error.message);
  }
  try {
    const result = await api("/api/health/ready");
    readiness.className = result.status === "ready" ? "integrity-ok" : "integrity-bad";
    readiness.textContent = result.status === "ready"
      ? "API and encrypted database checks are passing."
      : "The backend database is not ready.";
  } catch (error) {
    showError(readiness, error.message);
  }
}

document.querySelector("#device-list").addEventListener("click", async event => {
  const button = event.target.closest("button.revoke-device");
  if (!button) return;
  if (!window.confirm("Revoke this device and remove all of its automation grants?")) return;
  button.disabled = true;
  try {
    await api(`/api/v1/devices/${encodeURIComponent(button.dataset.deviceId)}/revoke`, {
      method: "POST",
    });
    await Promise.all([loadSecurity(), loadRotations()]);
  } catch (error) {
    showError(document.querySelector("#device-list"), error.message);
  }
});

async function verifyAudit() {
  const container = document.querySelector("#audit-status");
  try {
    const result = await api("/api/v1/audit/verify");
    container.className = result.valid ? "integrity-ok" : "integrity-bad";
    container.textContent = result.valid
      ? `Verified ${result.events_checked} chained events. No tampering detected.`
      : `Audit chain failed at event ${result.first_invalid_sequence}.`;
  } catch (error) {
    showError(container, error.message);
  }
}

async function createAgentEnrollment() {
  const container = document.querySelector("#enrollment-code");
  try {
    const result = await api("/api/v1/devices/enrollment-code", { method: "POST" });
    document.querySelector("#enrollment-code-value").textContent = result.code;
    document.querySelector("#enrollment-code-expiry").textContent =
      `Expires ${new Date(result.expires_at).toLocaleTimeString()}. It works once.`;
    container.hidden = false;
  } catch (error) {
    container.hidden = false;
    showError(container, error.message);
  }
}

function showError(container, message) {
  container.className = "integrity-bad";
  container.textContent = message;
}

function escapeText(value) {
  const span = document.createElement("span");
  span.textContent = String(value);
  return span.innerHTML;
}

async function loadView(view) {
  if (!isAuthenticated) return;
  if (view === "overview") await refreshOverview();
  if (view === "vault") await loadVault();
  if (view === "rotations") await loadRotations();
  if (view === "connections") await loadConnections();
  if (view === "security") await loadSecurity();
}

document.querySelector("#connect-button").addEventListener("click", async () => {
  if (!isAuthenticated) return connectDialog.showModal();
  await api("/api/v1/auth/logout", { method: "POST" });
  isAuthenticated = false;
  lockVault();
  await refreshAuthState();
});
document.querySelector("#unlock-button").addEventListener("click", async () => {
  if (!vaultKey) return unlockDialog.showModal();
  lockVault();
  await loadVault();
});
document.querySelector("#unlock-form").addEventListener("submit", async event => {
  event.preventDefault();
  const error = document.querySelector("#unlock-error");
  try {
    await unlockVault(document.querySelector("#passphrase-input").value);
    error.textContent = "";
    document.querySelector("#passphrase-input").value = "";
    unlockDialog.close();
    await loadVault();
  } catch {
    error.textContent = "The passphrase could not unlock this local vault.";
  }
});
document.querySelector("#add-button").addEventListener("click", () => {
  if (!isAuthenticated) return connectDialog.showModal();
  if (!vaultKey) return unlockDialog.showModal();
  credentialDialog.showModal();
});
document.querySelector("#credential-form").addEventListener("submit", async event => {
  event.preventDefault();
  const error = document.querySelector("#credential-error");
  try {
    const site = new URL(document.querySelector("#credential-site").value);
    if (site.protocol !== "https:") throw new Error("The site URL must use HTTPS.");
    const payload = {
      title: document.querySelector("#credential-title").value.trim(),
      username: document.querySelector("#credential-username").value.trim(),
      password: document.querySelector("#credential-password").value,
    };
    const encrypted = await encryptWithKey(vaultKey, payload);
    const itemId = crypto.randomUUID();
    const labels = site.hostname.split(".");
    const provider = (labels.length > 1 ? labels[labels.length - 2] : labels[0])
      .replace(/[^a-z0-9_-]/gi, "-").toLowerCase();
    await api("/api/v1/vault/items", { method: "PUT", body: JSON.stringify({
      item_id: itemId, provider_id: provider, site_origin: site.origin,
      kdf_salt: vaultItemSalt,
      nonce: encrypted.nonce, ciphertext: encrypted.ciphertext, key_version: 2,
    }) });
    await api("/api/v1/rotation/policies", { method: "PUT", body: JSON.stringify({
      item_id: itemId,
      interval_days: Number(document.querySelector("#credential-interval").value),
      approval_mode: document.querySelector("#credential-approval").value,
      enabled: true,
    }) });
    event.target.reset();
    error.textContent = "";
    credentialDialog.close();
    await refreshOverview();
  } catch (caught) {
    error.textContent = caught.message;
  }
});
async function scanRotations() {
  try {
    await api("/api/v1/rotation/scan", { method: "POST" });
    await Promise.all([refreshOverview(), loadRotations()]);
  } catch {
    if (!connectDialog.open) connectDialog.showModal();
  }
}
document.querySelector("#scan-button").addEventListener("click", scanRotations);
document.querySelector("#rotation-scan-button").addEventListener("click", scanRotations);
document.querySelector("#verify-audit-button").addEventListener("click", verifyAudit);
document.querySelector("#enroll-agent-button").addEventListener("click", createAgentEnrollment);
document.querySelector("#logout-all-button").addEventListener("click", async () => {
  if (!window.confirm("Sign out every browser session, including this one?")) return;
  await api("/api/v1/auth/logout-all", { method: "POST" });
  isAuthenticated = false;
  lockVault();
  await refreshAuthState();
  connectDialog.showModal();
});
document.querySelector("#change-passphrase-button").addEventListener("click", () => {
  if (!vaultKey) return unlockDialog.showModal();
  document.querySelector("#passphrase-change-dialog").showModal();
});
document.querySelector("#passphrase-change-form").addEventListener("submit", async event => {
  event.preventDefault();
  const error = document.querySelector("#passphrase-change-error");
  const current = document.querySelector("#current-passphrase").value;
  const next = document.querySelector("#new-passphrase").value;
  const confirmation = document.querySelector("#confirm-passphrase").value;
  try {
    if (next.length < 12) throw new Error("Use at least 12 characters.");
    if (next !== confirmation) throw new Error("The new passphrases do not match.");
    const envelope = await getKeyEnvelope();
    if (!envelope) throw new Error("Unlock the vault before changing its passphrase.");
    const currentKey = await openKeyEnvelope(current, envelope);
    const matches = currentKey.length === vaultKeyBytes.length &&
      currentKey.every((value, index) => value === vaultKeyBytes[index]);
    currentKey.fill(0);
    if (!matches) throw new Error("The current passphrase is incorrect.");
    const replacement = await createKeyEnvelope(next, vaultKeyBytes);
    await api("/api/v1/vault/key-envelope", {
      method: "PUT", body: JSON.stringify(replacement),
    });
    event.target.reset();
    error.textContent = "";
    document.querySelector("#passphrase-change-dialog").close();
  } catch (caught) {
    error.textContent = caught.message;
  }
});
async function activateView(view) {
  document.querySelectorAll(".nav-item").forEach(item => item.classList.remove("active"));
  document.querySelectorAll(".view").forEach(view => view.classList.remove("active-view"));
  document.querySelector(`.nav-item[data-view="${view}"]`)?.classList.add("active");
  document.querySelector(`#${view}`)?.classList.add("active-view");
  await loadView(view);
}

document.querySelectorAll(".nav-item").forEach(button => button.addEventListener("click", async () => {
  await activateView(button.dataset.view);
}));

for (const eventName of ["pointerdown", "keydown"]) {
  document.addEventListener(eventName, scheduleVaultLock, { passive: true });
}
document.addEventListener("visibilitychange", () => {
  if (document.hidden) lockVault();
});
window.addEventListener("pagehide", lockVault);

updateVaultLockUi();
refreshAuthState();
