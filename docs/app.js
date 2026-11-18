// Arrabona Pass Mobil - csak olvashato trezor-nezo iPhone-ra (es barmilyen modern bongeszore).
// A trezorfajl (ArrabonaPass_mobil.apv) titkositva van a telefonon is; feloldas helyben,
// internet nelkul: Argon2id (argon2.js) -> AES-256-GCM (WebCrypto). Az app semmit nem kuld sehova.
"use strict";

const APP_VERSION = "1.0.0";
const MAGIC = new TextEncoder().encode("ARRABONAPASS\x01");
const MAX_HEADER = 4096;

// ======================================================================
//  Trezor: beolvasas + feloldas (a Pass vault.py formatuma)
// ======================================================================
class VaultError extends Error {}

function b64d(s) {
  const bin = atob(s); const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function parseVault(raw) {
  raw = new Uint8Array(raw);
  if (raw.length < MAGIC.length + 4 || !MAGIC.every((b, i) => raw[i] === b))
    throw new VaultError("Ez nem Arrabona Pass trezor, vagy megsérült.");
  let pos = MAGIC.length;
  const hlen = ((raw[pos] << 24) | (raw[pos + 1] << 16) | (raw[pos + 2] << 8) | raw[pos + 3]) >>> 0;
  pos += 4;
  if (hlen > MAX_HEADER || raw.length < pos + hlen + 12 + 16)
    throw new VaultError("A trezorfájl megsérült (rossz fejléc).");
  let hdr;
  try { hdr = JSON.parse(new TextDecoder().decode(raw.subarray(pos, pos + hlen))); }
  catch (e) { throw new VaultError("A trezorfájl megsérült (olvashatatlan fejléc)."); }
  pos += hlen;
  if (hdr.kdf !== "argon2id") throw new VaultError("Ismeretlen kulcsszármaztatás a trezorban.");
  const t = +hdr.t, m = +hdr.m, p = +hdr.p;
  if (!(t >= 1 && t <= 50 && m >= 8192 && m <= 4 * 1024 * 1024 && p >= 1 && p <= 16))
    throw new VaultError("Érvénytelen trezor-fejléc.");
  return { hdr, aad: raw.slice(0, pos), nonce: raw.slice(pos, pos + 12), ct: raw.slice(pos + 12) };
}

async function deriveKey(password, hdr, onProgress) {
  const pw = new TextEncoder().encode(password.normalize("NFC"));
  return Argon2.argon2id({ password: pw, salt: b64d(hdr.salt), t: +hdr.t, m: +hdr.m, p: +hdr.p,
                           hashLen: 32, onProgress });
}

async function decryptVault(parsed, rawKey) {
  const key = await crypto.subtle.importKey("raw", rawKey, "AES-GCM", false, ["decrypt"]);
  let plain;
  try {
    plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: parsed.nonce, additionalData: parsed.aad,
                                          tagLength: 128 }, key, parsed.ct);
  } catch (e) { const er = new VaultError("Hibás mesterjelszó."); er.wrong = true; throw er; }
  const data = JSON.parse(new TextDecoder().decode(plain));
  data.entries = (data.entries || []).map(e => Object.assign(
    { title: "", username: "", password: "", url: "", notes: "", category: "", favorite: false, type: "login" }, e));
  return data;
}

// ======================================================================
//  Jelszokor, kartyalejarat (a Pass health.py-ja szerint)
// ======================================================================
function parseTs(ts) {
  const m = /^(\d{4})-(\d\d)-(\d\d) (\d\d):(\d\d):(\d\d)/.exec(ts || "");
  return m ? new Date(+m[1], m[2] - 1, +m[3], +m[4], +m[5], +m[6]) : null;
}
function passwordDate(e) {
  if (e.pw_changed) return e.pw_changed;
  const h = e.history || [];
  if (h.length && h[0].changed) return h[0].changed;
  return e.created || "";
}
function ageDays(ts) { const d = parseTs(ts); return d ? Math.max(0, Math.floor((Date.now() - d) / 864e5)) : null; }
function humanAge(days) {
  if (days == null) return "ismeretlen ideje";
  if (days < 1) return "ma";
  if (days < 45) return `${days} napja`;
  const months = Math.round(days / 30.44);
  if (months < 12) return `${months} hónapja`;
  const y = Math.floor(months / 12), mo = months % 12;
  return mo ? `${y} év ${mo} hónapja` : `${y} éve`;
}
function cardStatus(exp, warnDays) {
  const m = /^(\d\d)\/(\d\d)$/.exec(exp || "");
  if (!m) return null;
  const last = new Date(2000 + +m[2], +m[1], 0);          // a honap utolso napja
  const today = new Date(); today.setHours(0, 0, 0, 0);
  if (last < today) return ["expired", `LEJÁRT kártya (${exp})`];
  const left = Math.round((last - today) / 864e5);
  if (warnDays && left <= warnDays) return ["expiring", `Hamarosan lejár: ${exp} (${left} nap múlva)`];
  return null;
}

if (typeof module !== "undefined") {    // node-os teszt
  module.exports = { parseVault, deriveKey, decryptVault, humanAge, cardStatus, passwordDate };
}

// ======================================================================
//  Tarolas a telefonon (IndexedDB) - csak titkositott adat kerul ide
// ======================================================================
const DB = (() => {
  let dbp = null;
  function open() {
    if (!dbp) dbp = new Promise((res, rej) => {
      const r = indexedDB.open("arrabona-pass-mobil", 1);
      r.onupgradeneeded = () => r.result.createObjectStore("kv");
      r.onsuccess = () => res(r.result);
      r.onerror = () => rej(r.error);
    });
    return dbp;
  }
  async function op(mode, fn) {
    const db = await open();
    return new Promise((res, rej) => {
      const tx = db.transaction("kv", mode); const st = tx.objectStore("kv");
      const req = fn(st);
      tx.oncomplete = () => res(req && req.result);
      tx.onerror = () => rej(tx.error);
    });
  }
  return {
    get: k => op("readonly", s => s.get(k)),
    set: (k, v) => op("readwrite", s => s.put(v, k)),
    del: k => op("readwrite", s => s.delete(k)),
  };
})();

// ======================================================================
//  Face ID (WebAuthn passkey + PRF): a trezor kulcsat egy csak Face ID-val
//  elerheto, a passkeyhez kotott titokkal csomagoljuk be.
// ======================================================================
const Hello = {
  supported() { return !!(window.PublicKeyCredential && navigator.credentials); },

  async _wrapKey(prf, saltForAad) {
    const base = await crypto.subtle.importKey("raw", prf, "HKDF", false, ["deriveKey"]);
    return crypto.subtle.deriveKey(
      { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0),
        info: new TextEncoder().encode("ArrabonaPass Mobil FaceID v1") },
      base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  },

  async _prf(credId, prfSalt) {
    const a = await navigator.credentials.get({ publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      allowCredentials: [{ type: "public-key", id: credId }],
      userVerification: "required", timeout: 60000,
      extensions: { prf: { eval: { first: prfSalt } } } } });
    const r = a.getClientExtensionResults().prf;
    if (!r || !r.results || !r.results.first) throw new Error("noprf");
    return new Uint8Array(r.results.first);
  },

  async enable(rawKey, vaultSalt) {
    const userId = crypto.getRandomValues(new Uint8Array(16));
    const prfSalt = crypto.getRandomValues(new Uint8Array(32));
    const cred = await navigator.credentials.create({ publicKey: {
      rp: { name: "Arrabona Pass Mobil", id: location.hostname },
      user: { id: userId, name: "Arrabona Pass", displayName: "Arrabona Pass Mobil" },
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      pubKeyCredParams: [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -257 }],
      authenticatorSelection: { authenticatorAttachment: "platform", residentKey: "required",
                                userVerification: "required" },
      timeout: 60000, extensions: { prf: { eval: { first: prfSalt } } } } });
    const ext = cred.getClientExtensionResults().prf;
    if (!ext || ext.enabled === false) throw new Error("noprf");
    const credId = new Uint8Array(cred.rawId);
    // nehany iOS-verzio letrehozaskor nem ad PRF-eredmenyt: ilyenkor egy azonnali Face ID kell
    const prf = ext.results && ext.results.first ? new Uint8Array(ext.results.first)
                                                  : await this._prf(credId, prfSalt);
    const wk = await this._wrapKey(prf);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const wrapped = new Uint8Array(await crypto.subtle.encrypt(
      { name: "AES-GCM", iv, additionalData: new TextEncoder().encode(vaultSalt) }, wk, rawKey));
    await DB.set("hello", { credId, prfSalt, iv, wrapped, vaultSalt });
  },

  async unlock() {
    const h = await DB.get("hello");
    if (!h) throw new Error("nincs");
    const prf = await this._prf(h.credId, h.prfSalt);
    const wk = await this._wrapKey(prf);
    return { rawKey: new Uint8Array(await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: h.iv, additionalData: new TextEncoder().encode(h.vaultSalt) }, wk, h.wrapped)),
      vaultSalt: h.vaultSalt };
  },

  async disable() { await DB.del("hello"); },
};

// ======================================================================
//  Felulet
// ======================================================================
if (typeof document !== "undefined") (function () {
  const $ = id => document.getElementById(id);
  const S = { vault: null, parsed: null, data: null, filter: ["all"], cat: "", q: "",
              hiddenAt: 0, lastAct: Date.now(), clipTimer: null, current: null,
              settings: { hide: 60, idle: 180, clip: 20, maxAge: 365, cardWarn: 60 } };

  // ---------- segedek ----------
  function el(tag, attrs, ...kids) {
    const e = document.createElement(tag);
    for (const [k, val] of Object.entries(attrs || {})) {
      if (k === "class") e.className = val;
      else if (k.startsWith("on")) e.addEventListener(k.slice(2), val);
      else if (val !== undefined && val !== null && val !== false) e.setAttribute(k, val);
    }
    for (const k of kids) if (k != null) e.append(k.nodeType ? k : String(k));
    return e;
  }
  let toastT = null;
  function toast(msg, ms = 2200) {
    const t = $("toast"); t.textContent = msg; t.hidden = false;
    clearTimeout(toastT); toastT = setTimeout(() => { t.hidden = true; }, ms);
  }
  function show(view) {
    for (const v of ["v-lock", "v-list", "v-detail", "v-settings"]) $(v).hidden = v !== view;
    window.scrollTo(0, 0);
  }
  const PALETTE = ["#e74c3c", "#e67e22", "#d4a017", "#27ae60", "#16a085", "#2980b9", "#8e44ad",
                   "#c0392b", "#2c3e50", "#d35400", "#7f8c8d", "#1abc9c"];
  function color(seed) { let h = 0; for (const c of seed) h = (h * 31 + c.charCodeAt(0)) >>> 0; return PALETTE[h % PALETTE.length]; }
  function host(e) {
    for (let raw of [e.url, e.title]) {
      raw = (raw || "").trim().toLowerCase(); if (!raw) continue;
      try { const h = new URL(raw.includes("://") ? raw : "https://" + raw).hostname.replace(/^www\./, "");
            if (h.includes(".")) return h; } catch (_) {}
    }
    return "";
  }
  function fmtDate(ms) {
    const d = new Date(ms);
    return d.toLocaleDateString("hu-HU") + " " + d.toLocaleTimeString("hu-HU", { hour: "2-digit", minute: "2-digit" });
  }

  // ---------- beallitasok ----------
  async function loadSettings() {
    const s = await DB.get("settings"); if (s) Object.assign(S.settings, s);
    $("s-hide").value = S.settings.hide; $("s-idle").value = S.settings.idle; $("s-clip").value = S.settings.clip;
  }
  for (const [id, k] of [["s-hide", "hide"], ["s-idle", "idle"], ["s-clip", "clip"]])
    $(id).addEventListener("change", () => { S.settings[k] = +$(id).value; DB.set("settings", S.settings); });

  // ---------- trezor betoltese ----------
  async function refreshLockScreen() {
    S.vault = await DB.get("vault");
    const hello = await DB.get("hello");
    $("lock-novault").hidden = !!S.vault;
    $("lock-form").hidden = !S.vault;
    $("b-faceid").hidden = !(S.vault && hello);
    $("lock-info").textContent = S.vault
      ? `Trezor: ${S.vault.name} · mentve ${fmtDate(S.vault.modified)}` : "Mobil · csak olvasható";
    $("lock-err").textContent = "";
  }
  $("file").addEventListener("change", async ev => {
    const f = ev.target.files && ev.target.files[0];
    ev.target.value = "";
    if (!f) return;
    try {
      if (f.size > 64 * 1024 * 1024) throw new VaultError("Ez a fájl túl nagy egy trezorhoz.");
      const raw = new Uint8Array(await f.arrayBuffer());
      const parsed = parseVault(raw);
      const old = await DB.get("vault");
      await DB.set("vault", { raw, name: f.name, modified: f.lastModified || Date.now(), loaded: Date.now() });
      const hello = await DB.get("hello");
      if (hello && hello.vaultSalt !== parsed.hdr.salt) {        // uj mesterjelszo a gepen
        await Hello.disable();
        toast("A mesterjelszó megváltozott – a Face ID-t újra be kell kapcsolni.", 4000);
      } else toast(old ? "Trezor frissítve." : "Trezor betöltve.");
      lock(true);
    } catch (e) {
      toast(e instanceof VaultError ? e.message : "A fájl nem olvasható: " + e.message, 4000);
    }
  });

  // ---------- feloldas ----------
  function setBusy(b) {
    $("b-unlock").disabled = b; $("b-faceid").disabled = b; $("pw").disabled = b;
    $("prog").hidden = !b; $("prog").firstElementChild.style.width = "0";
  }
  async function openWithKey(rawKey) {
    const parsed = parseVault(S.vault.raw);
    S.data = await decryptVault(parsed, rawKey);
    S.parsed = parsed;
    S.key = rawKey;
    S.lastAct = Date.now();
    $("pw").value = "";
    S.filter = ["all"]; S.cat = ""; S.q = ""; $("q").value = "";
    renderList(); show("v-list");
  }
  $("lock-form").addEventListener("submit", async ev => {
    ev.preventDefault();
    const pw = $("pw").value;
    if (!pw) { $("lock-err").textContent = "Add meg a mesterjelszót."; return; }
    $("pw").blur();
    setBusy(true); $("lock-err").textContent = "";
    try {
      const parsed = parseVault(S.vault.raw);
      const key = await deriveKey(pw, parsed.hdr, p => { $("prog").firstElementChild.style.width = (p * 100) + "%"; });
      await openWithKey(key);
    } catch (e) {
      $("lock-err").textContent = e instanceof VaultError ? e.message : "Hiba: " + e.message;
      $("pw").select();
    } finally { setBusy(false); }
  });
  async function faceUnlock() {
    $("lock-err").textContent = "";
    try {
      const { rawKey } = await Hello.unlock();
      await openWithKey(rawKey);
    } catch (e) {
      if (e instanceof VaultError && e.wrong) {
        await Hello.disable(); await refreshLockScreen();
        $("lock-err").textContent = "A Face ID-s kulcs már nem jó (új mesterjelszó?). Lépj be jelszóval.";
      } else if (e.name !== "NotAllowedError") {
        $("lock-err").textContent = "Face ID nem sikerült – lépj be a mesterjelszóval.";
      }
    }
  }

  // ---------- zarolas ----------
  function lock(silent) {
    clearClipSoon(true);
    S.data = null; S.parsed = null; S.key = null; S.current = null;
    $("list").replaceChildren(); $("d-body").replaceChildren();
    refreshLockScreen().then(() => {
      show("v-lock");
      if (!silent && S.vault && !$("b-faceid").hidden) faceUnlock();
    });
  }
  document.addEventListener("visibilitychange", () => {
    if (document.hidden) {
      document.body.classList.add("covered");      // az app-valtoban ne latszodjon semmi
      S.hiddenAt = Date.now();
      if (S.data && S.settings.hide === 0) lock(true);
    } else {
      document.body.classList.remove("covered");
      if (S.data && (Date.now() - S.hiddenAt) / 1000 >= S.settings.hide) lock(false);
    }
  });
  window.addEventListener("pagehide", () => document.body.classList.add("covered"));
  window.addEventListener("pageshow", () => document.body.classList.remove("covered"));
  for (const evn of ["pointerdown", "keydown", "scroll"])
    document.addEventListener(evn, () => { S.lastAct = Date.now(); }, { passive: true });
  setInterval(() => {
    if (S.data && (Date.now() - S.lastAct) / 1000 >= S.settings.idle) { lock(true); toast("Zárolva (tétlenség)."); }
  }, 5000);

  // ---------- masolas ----------
  async function copy(val, what) {
    if (!val) { toast(`Nincs ${what.toLowerCase()}.`); return; }
    try {
      await navigator.clipboard.writeText(val);
      toast(S.settings.clip ? `${what} másolva – ${S.settings.clip} mp múlva törlöm` : `${what} másolva`);
      clearClipSoon(false, val);
    } catch (e) { toast("Nem sikerült másolni."); }
  }
  function clearClipSoon(now, val) {
    clearTimeout(S.clipTimer); S.clipTimer = null;
    if (now || !S.settings.clip) return;
    S.clipTimer = setTimeout(() => {
      if (document.hasFocus()) navigator.clipboard.writeText("").catch(() => {});
    }, S.settings.clip * 1000);
  }

  // ---------- lista ----------
  function rowSub(e) {
    if (e.type === "card") {
      const n = e.card_number || "";
      return [e.card_holder, n.length >= 4 ? "•••• " + n.slice(-4) : ""].filter(Boolean).join(" · ");
    }
    if (e.type === "note") return "Biztonságos jegyzet";
    return e.username || host(e) || "";
  }
  function ageMark(e) {
    if (e.type === "card" && e.card_exp) {
      const st = cardStatus(e.card_exp, S.settings.cardWarn);
      return st ? (st[0] === "expired" ? "⚠" : "⏱") : "";
    }
    if (e.type === "login" && e.password) {
      const d = ageDays(passwordDate(e));
      return d != null && d > S.settings.maxAge ? "⏱" : "";
    }
    return "";
  }
  function matches(e) {
    const f = S.filter;
    if (!S.q) {
      if (f[0] === "fav" && !e.favorite) return false;
      if (f[0] === "type" && e.type !== f[1]) return false;
      if (S.cat === "\u0000" ? e.category : (S.cat && e.category !== S.cat)) return false;
    } else {
      const hay = [e.title, e.username, e.url, e.notes, e.category, e.card_holder].join(" ").toLowerCase();
      if (!S.q.split(/\s+/).every(w => hay.includes(w))) return false;
    }
    return true;
  }
  function renderChips() {
    const ents = S.data.entries, types = {};
    for (const e of ents) types[e.type] = (types[e.type] || 0) + 1;
    const chips = [[["all"], `Összes ${ents.length}`], [["fav"], `★ ${ents.filter(e => e.favorite).length}`]];
    if (types.note || types.card) {
      chips.push([["type", "login"], `Bejelentkezés ${types.login || 0}`]);
      if (types.note) chips.push([["type", "note"], `Jegyzet ${types.note}`]);
      if (types.card) chips.push([["type", "card"], `Kártya ${types.card}`]);
    }
    $("chips").replaceChildren(...chips.map(([k, t]) => el("button", {
      class: "chip" + (k.join() === S.filter.join() ? " on" : ""),
      onclick: () => { S.filter = k; renderList(); } }, t)));
    const cats = [...new Set([...(S.data.categories || []), ...ents.map(e => e.category)].filter(Boolean))]
      .sort((a, b) => a.localeCompare(b, "hu"));
    const sel = $("cat");
    sel.replaceChildren(el("option", { value: "" }, "Minden kategória"),
      ...cats.map(c => el("option", { value: c }, c)),
      ents.some(e => !e.category) && cats.length ? el("option", { value: "\u0000" }, "Kategória nélkül") : null);
    if (S.cat && S.cat !== "\u0000" && !cats.includes(S.cat)) S.cat = "";
    sel.value = S.cat;
    $("catrow").hidden = !cats.length;
  }
  function renderList() {
    if (!S.data) return;
    renderChips();
    const items = S.data.entries.filter(matches).sort((a, b) =>
      (b.favorite - a.favorite) || a.title.localeCompare(b.title, "hu", { sensitivity: "base" }));
    const ul = $("list");
    if (!items.length) {
      ul.replaceChildren(el("li", { class: "empty" }, S.q ? "Nincs találat." : "Ebben a nézetben nincs bejegyzés."));
    } else {
      ul.replaceChildren(...items.map(e => {
        const av = e.type === "note" ? el("div", { class: "av note" }, "✎")
          : e.type === "card" ? el("div", { class: "av card" }, "▭")
          : el("div", { class: "av" }, ((e.title.match(/[\p{L}\p{N}]/u) || ["?"])[0]).toUpperCase());
        if (e.type === "login") av.style.background = color(host(e) || e.title);   // CSP: csak CSSOM
        const mk = ageMark(e);
        return el("li", { onclick: () => openDetail(e) }, av,
          el("div", { class: "li-main" }, el("div", { class: "li-t" }, e.title), el("div", { class: "li-s" }, rowSub(e))),
          mk ? el("span", { class: "mark" }, mk) : null,
          e.favorite ? el("span", { class: "mark fav" }, "★") : null);
      }));
    }
    $("count").textContent = `${items.length} db`;
    $("synced").textContent = `Trezor: mentve ${fmtDate(S.vault.modified)} · betöltve ${fmtDate(S.vault.loaded)}`;
  }
  $("q").addEventListener("input", () => { S.q = $("q").value.trim().toLowerCase(); renderList(); });
  $("cat").addEventListener("change", () => { S.cat = $("cat").value; renderList(); });

  // ---------- reszletek ----------
  function field(label, value, opts = {}) {
    if (!value && !opts.always) return null;
    const v = el("div", { class: "f-v" + (opts.mono ? " mono" : "") + (opts.pre ? " pre" : "") });
    let shown = !opts.secret;
    const paint = () => {
      if (opts.link && shown) v.replaceChildren(el("a", { href: safeUrl(value), target: "_blank", rel: "noopener noreferrer" }, value));
      else v.textContent = shown ? (opts.fmt ? opts.fmt(value) : value) : "•".repeat(Math.min(12, Math.max(6, value.length)));
    };
    paint();
    const btns = [];
    if (opts.secret) {
      const b = el("button", { class: "mini", onclick: () => { shown = !shown; b.classList.toggle("on", shown); b.textContent = shown ? "Elrejt" : "Mutat"; paint(); } }, "Mutat");
      btns.push(b);
    }
    if (opts.copy !== false) btns.push(el("button", { class: "mini", onclick: () => copy(value, label) }, "Másol"));
    return el("div", { class: "f" }, el("div", { class: "f-l" }, label), el("div", { class: "f-row" }, v, ...btns));
  }
  function safeUrl(u) { const x = u.includes("://") ? u : "https://" + u; return /^https?:\/\//i.test(x) ? x : "#"; }
  function openDetail(e) {
    S.current = e;
    $("d-title").textContent = e.title;
    const parts = [];
    if (e.type === "card") {
      const st = e.card_exp ? cardStatus(e.card_exp, S.settings.cardWarn) : null;
      parts.push(el("div", { class: "card" },
        field("Kártyabirtokos", e.card_holder),
        field("Kártyaszám", e.card_number, { secret: true, mono: true, fmt: n => n.replace(/(.{4})/g, "$1 ").trim() }),
        field("Lejárat", e.card_exp, { mono: true }),
        field("CVC", e.card_cvv, { secret: true, mono: true }),
        field("PIN", e.card_pin, { secret: true, mono: true }),
        st ? el("div", { class: "age " + (st[0] === "expired" ? "bad" : "warn") }, (st[0] === "expired" ? "⚠ " : "⏱ ") + st[1]) : null));
      if (e.notes) parts.push(el("div", { class: "card" }, field("Megjegyzés", e.notes, { pre: true })));
    } else if (e.type === "note") {
      parts.push(el("div", { class: "card" }, field("Tartalom", e.notes, { pre: true, always: true })));
    } else {
      const pd = passwordDate(e), d = ageDays(pd), old = e.password && d != null && d > S.settings.maxAge;
      parts.push(el("div", { class: "card" },
        field("Felhasználónév", e.username),
        field("Jelszó", e.password, { secret: true, mono: true }),
        field("Weboldal", e.url, { link: true }),
        e.password ? el("div", { class: "age" + (old ? " warn" : "") },
          `Jelszó beállítva: ${pd.slice(0, 10)} (${humanAge(d)})` + (old ? " – ideje cserélni ⏱" : "")) : null));
      if (e.notes) parts.push(el("div", { class: "card" }, field("Megjegyzés", e.notes, { pre: true })));
    }
    const meta = [e.category ? "Kategória: " + e.category : "", e.favorite ? "★ Kedvenc" : "",
                  e.modified ? "Módosítva: " + e.modified.slice(0, 10) : ""].filter(Boolean).join(" · ");
    if (meta) parts.push(el("p", { class: "soft small center" }, meta));
    $("d-body").replaceChildren(...parts);
    show("v-detail");
  }

  // ---------- beallitasok nezet ----------
  async function openSettings() {
    const h = await DB.get("hello");
    $("s-faceid").checked = !!h;
    $("s-faceid").disabled = !Hello.supported();
    $("s-faceid-info").textContent = Hello.supported()
      ? (h ? "Be van kapcsolva. A kulcs csak Face ID-val nyitható ki ezen a telefonon."
           : "Bekapcsoláskor az iPhone egy kulcsot (passkey) hoz létre, Face ID-val védve.")
      : "Ez a böngésző nem támogatja.";
    $("s-vault").textContent = S.vault
      ? `${S.vault.name} · mentve ${fmtDate(S.vault.modified)} · betöltve ${fmtDate(S.vault.loaded)} · ${Math.round(S.vault.raw.length / 1024)} KB` : "";
    $("s-ver").textContent = `Arrabona Pass Mobil v${APP_VERSION} · csak olvasható`;
    show("v-settings");
  }
  $("s-faceid").addEventListener("change", async ev => {
    const on = ev.target.checked;
    try {
      if (on) {
        if (!S.key) throw new Error("lock");
        await Hello.enable(S.key, S.parsed.hdr.salt);
        toast("Face ID bekapcsolva.");
      } else { await Hello.disable(); toast("Face ID kikapcsolva."); }
    } catch (e) {
      ev.target.checked = !on;
      toast(e.message === "noprf"
        ? "Ez az iOS-verzió nem tud Face ID-s kulcsot adni a webappnak (iOS 18 vagy újabb kell)."
        : e.name === "NotAllowedError" ? "Megszakítva." : "Nem sikerült: " + e.message, 4500);
    }
    openSettings();
  });

  // ---------- gombok ----------
  document.addEventListener("click", ev => {
    const b = ev.target.closest("[data-act]"); if (!b) return;
    const act = b.dataset.act;
    if (act === "pick") $("file").click();
    else if (act === "faceid") faceUnlock();
    else if (act === "lock") lock(true);
    else if (act === "settings") openSettings();
    else if (act === "back") { S.current = null; $("d-body").replaceChildren(); renderList(); show("v-list"); }
    else if (act === "forget") {
      if (confirm("Törlöd a trezort erről a telefonról? (A gépen és a Proton Drive-on megmarad.)")) {
        DB.del("vault").then(() => Hello.disable()).then(() => { S.vault = null; lock(true); toast("Törölve."); });
      }
    }
  });

  // ---------- inditas ----------
  if ("serviceWorker" in navigator) navigator.serviceWorker.register("sw.js").catch(() => {});
  if (navigator.storage && navigator.storage.persist) navigator.storage.persist().catch(() => {});
  loadSettings().then(() => lock(false));
})();
