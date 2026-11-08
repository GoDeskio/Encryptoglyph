const sessionKey = "eg.session";
let session = sessionStorage.getItem(sessionKey) || "";

const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
document.documentElement.dataset.motion = reduce ? "reduce" : "full";
if (!reduce) {
  window.addEventListener("pointermove", (event) => {
    document.documentElement.style.setProperty("--px", `${event.clientX}px`);
    document.documentElement.style.setProperty("--py", `${event.clientY}px`);
  });
}

const $ = (id) => document.getElementById(id);

function b64encode(text) {
  const bytes = new TextEncoder().encode(text);
  let binary = "";
  bytes.forEach((byte) => {
    binary += String.fromCharCode(byte);
  });
  return btoa(binary);
}

function b64decode(value) {
  const binary = atob(value);
  const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
  return new TextDecoder().decode(bytes);
}

function looksSecret(text) {
  if (/(password|secret|api[_ -]?key|token|seed|private key|plaintext)\s*[:=]/i.test(text)) return true;
  return /[A-Za-z0-9+/]{40,}={0,2}/.test(text);
}

async function api(path, body, retry = true) {
  const headers = {};
  if (session) headers["x-eg-session"] = session;
  const options = { headers };
  if (body !== undefined) {
    headers["content-type"] = "application/json";
    options.method = "POST";
    options.body = JSON.stringify(body);
  }
  const response = await fetch(path, options);
  const data = await response.json().catch(() => ({}));
  if (response.status === 401 && retry && path !== "/v1/sessions") {
    session = "";
    sessionStorage.removeItem(sessionKey);
    await ensureSession();
    return api(path, body, false);
  }
  if (!response.ok) {
    const error = new Error(data.error || "request failed");
    error.status = response.status;
    throw error;
  }
  return data;
}

async function ensureSession() {
  if (session) return;
  const data = await api("/v1/sessions", {});
  session = data.session_id;
  sessionStorage.setItem(sessionKey, session);
}

function show(view) {
  document.querySelectorAll("[data-view-panel]").forEach((panel) => {
    panel.hidden = panel.dataset.viewPanel !== view;
  });
  document.querySelectorAll("[data-nav]").forEach((button) => {
    if (button.dataset.nav === view) button.setAttribute("aria-current", "page");
    else button.removeAttribute("aria-current");
  });
  $("nav-links").classList.remove("open");
  $("menu").setAttribute("aria-expanded", "false");
  if (view === "keys") refreshKeys();
  if (view === "custody") refreshCustody();
}

function contextBody(extra) {
  return {
    tenant: $("tenant").value.trim(),
    purpose: "field",
    table: $("table").value.trim(),
    record_id: $("record").value.trim(),
    field: $("field").value.trim(),
    schema_version: 1,
    ...extra,
  };
}

async function refreshKeys() {
  await ensureSession();
  const data = await api("/v1/keys");
  const list = $("key-list");
  list.replaceChildren();
  if (!data.keys.length) {
    const empty = document.createElement("p");
    empty.className = "glass";
    empty.textContent = "No keys yet.";
    list.append(empty);
    return;
  }
  data.keys.forEach((row) => {
    const card = document.createElement("article");
    card.className = "glass key";
    const text = document.createElement("div");
    const title = document.createElement("strong");
    title.textContent = row.current ? `${row.kid} · current` : row.kid;
    const code = document.createElement("code");
    code.textContent = row.fingerprint;
    text.append(title, document.createElement("br"), code);
    card.append(text);
    if (!row.current) {
      const button = document.createElement("button");
      button.className = "btn";
      button.type = "button";
      button.textContent = "Shred";
      button.dataset.kid = row.kid;
      button.addEventListener("click", () => shred(row.kid));
      card.append(button);
    }
    list.append(card);
  });
}

async function shred(kid) {
  const confirm = $("shred-confirm").value.trim();
  try {
    const grant = await api("/v1/reauth", { kid, confirm_fingerprint: confirm });
    const result = await api("/v1/shred", { kid, grant: grant.grant });
    $("key-status").textContent = `Shredded ${result.shredded}. Fingerprint ${result.fingerprint}.`;
    $("shred-confirm").value = "";
    await refreshKeys();
  } catch (error) {
    $("key-status").textContent = error.message;
  }
}

async function refreshCustody() {
  const data = await api("/v1/status");
  const list = $("custody-status");
  list.replaceChildren();
  [
    ["Custody", data.custody],
    ["OpenBao", data.openbao],
    ["Backup target", data.restic],
    ["AEAD", data.aead],
    ["Agent", data.ollama ? "deterministic, Ollama available" : "deterministic"],
  ].forEach(([name, value]) => {
    const term = document.createElement("dt");
    term.textContent = name;
    const detail = document.createElement("dd");
    detail.textContent = String(value);
    list.append(term, detail);
  });
}

function addBubble(text, role) {
  const line = document.createElement("p");
  line.className = `bubble ${role}`;
  line.textContent = text;
  $("transcript").append(line);
}

async function runAgent(text) {
  const trimmed = text.trim();
  if (!trimmed) return;
  if (looksSecret(trimmed)) {
    addBubble("That stays out of the assistant. Use the Seal form for values.", "agent");
    $("agent-input").value = "";
    return;
  }
  addBubble(trimmed, "user");
  $("agent-input").value = "";
  const data = await api("/v1/agent", { message: trimmed });
  addBubble(data.reply, "agent");
  for (const action of data.actions || []) {
    if (action.op === "navigate") show(action.view);
    if (action.op === "health") {
      const health = await fetch("/healthz").then((response) => response.json());
      addBubble(`Health is ${health.status}. Build ${health.build || "local"}.`, "agent");
    }
    if (action.op === "new-key") {
      await ensureSession();
      const key = await api("/v1/keys", {});
      addBubble(`Key ${key.kid}. Fingerprint ${key.fingerprint}.`, "agent");
      await refreshKeys();
    }
    if (action.op === "update") await checkUpdate();
  }
}

async function checkUpdate() {
  const data = await api("/v1/update");
  const target = $("update-status");
  if (data.state === "unknown") {
    target.textContent = `This build is ${data.current}. The release feed did not answer.`;
  } else if (data.update_available) {
    target.textContent = `Update ${data.latest} is published. This build is ${data.current}.`;
  } else {
    target.textContent = `This build is ${data.current} and matches the latest release.`;
  }
}

document.querySelectorAll("[data-nav]").forEach((button) => {
  button.addEventListener("click", () => show(button.dataset.nav));
});

$("menu").addEventListener("click", () => {
  const open = $("nav-links").classList.toggle("open");
  $("menu").setAttribute("aria-expanded", String(open));
});

$("hero-update").addEventListener("click", () => {
  checkUpdate().catch((error) => {
    $("update-status").textContent = error.message;
  });
});

$("seal-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    await ensureSession();
    const value = $("plaintext").value;
    if (!value) {
      $("seal-status").textContent = "Enter a value to seal.";
      return;
    }
    const sealed = await api("/v1/seal", contextBody({ plaintext_b64: b64encode(value) }));
    $("ciphertext").value = sealed.blob_b64;
    $("seal-status").textContent = `Sealed ${sealed.plaintext_bytes} bytes with ${sealed.kid}. Fingerprint ${sealed.fingerprint}.`;
    $("opened").textContent = "";
  } catch (error) {
    $("seal-status").textContent = error.message;
  }
});

$("open-blob").addEventListener("click", async () => {
  try {
    await ensureSession();
    const opened = await api("/v1/open", contextBody({ blob_b64: $("ciphertext").value.trim() }));
    $("opened").textContent = b64decode(opened.plaintext_b64);
    $("seal-status").textContent = `Opened ${opened.bytes} bytes in this panel.`;
  } catch (error) {
    $("seal-status").textContent = error.message;
  }
});

$("rewrap-blob").addEventListener("click", async () => {
  try {
    await ensureSession();
    const fresh = await api("/v1/rewrap", contextBody({ blob_b64: $("ciphertext").value.trim() }));
    $("ciphertext").value = fresh.blob_b64;
    $("seal-status").textContent = fresh.rewrapped ? `Rewrapped under ${fresh.kid}.` : "Already on the current key.";
  } catch (error) {
    $("seal-status").textContent = error.message;
  }
});

$("index-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    await ensureSession();
    const value = $("index-value").value;
    const indexed = await api("/v1/blind-index", {
      tenant: $("tenant").value.trim(),
      field: $("field").value.trim(),
      value,
    });
    $("index-status").textContent = `Index ready (${indexed.bytes} bytes hashed).`;
    $("index-status").dataset.index = indexed.index_b64;
  } catch (error) {
    $("index-status").textContent = error.message;
  }
});

$("new-key").addEventListener("click", async () => {
  try {
    await ensureSession();
    const key = await api("/v1/keys", {});
    $("key-status").textContent = `Created ${key.kid}. Fingerprint ${key.fingerprint}.`;
    await refreshKeys();
  } catch (error) {
    $("key-status").textContent = error.message;
  }
});

$("backup").addEventListener("click", async () => {
  try {
    await ensureSession();
    const file = await api("/v1/backup", {});
    const link = document.createElement("a");
    link.href = `data:application/octet-stream;base64,${file.blob_b64}`;
    link.download = file.filename;
    link.click();
    $("backup-status").textContent = `Sealed inventory downloaded. ${file.note}`;
  } catch (error) {
    $("backup-status").textContent = error.message;
  }
});

document.querySelectorAll("[data-agent]").forEach((button) => {
  button.addEventListener("click", () => {
    runAgent(button.dataset.agent).catch((error) => addBubble(error.message, "agent"));
  });
});

$("agent-form").addEventListener("submit", (event) => {
  event.preventDefault();
  runAgent($("agent-input").value).catch((error) => addBubble(error.message, "agent"));
});

async function boot() {
  const status = await api("/v1/status");
  $("foot-version").textContent = status.version;
  const integration = await api("/v1/integration");
  $("snippet-python").textContent = integration.python;
  $("snippet-http").textContent = integration.http;
  show("home");
}

boot().catch((error) => {
  $("update-status").textContent = error.message;
});
