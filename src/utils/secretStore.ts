/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

// Goal #1 (secrets-at-rest encryption): the panel persists SSH passwords, the agent
// secret, and similar credentials into plaintext JSON files (app-config.json,
// agent-config.json, …) sitting in process.cwd(). On the Windows panel host the usual
// `chmod 0600` hardening is a no-op, so any other local user can read those files. This
// module encrypts secret VALUES at rest with AES-256-GCM under a per-install random
// master key, while staying fully backward-compatible: decryptSecret() passes through
// any value that is not one of our tagged tokens, so existing plaintext configs keep
// working and only get migrated to ciphertext on the next write.
//
// CRITICAL robustness rule (never lock the user out of their own config): if anything
// in the key lifecycle fails — DPAPI unavailable, unwritable certs/ dir, corrupt key —
// encryptSecret() returns the plaintext UNCHANGED rather than throwing, and
// decryptSecret() of a plaintext value always works regardless of key state.

import crypto from "crypto";
import fs from "fs";
import path from "path";
import { spawnSync } from "child_process";

// Tagged-token prefix, mirroring the existing "scrypt$…" tagged-hash convention in
// server.ts. Versioned so the on-disk format can evolve without ambiguity.
const TOKEN_PREFIX = "nfmenc:v1:";

// AES-256-GCM parameters.
const KEY_LEN = 32; // 256-bit master key
const IV_LEN = 12; // 96-bit IV (GCM recommended)
const TAG_LEN = 16; // 128-bit auth tag

// Master key lives alongside the panel's own TLS material in certs/ (same dir as
// server.crt/server.key in server.ts — already gitignored and covered by the
// static-deny middleware). Resolved against process.cwd() to match how server.ts
// resolves CONFIG_FILE / CERT_DIR.
const CERT_DIR = path.join(process.cwd(), "certs");
const MASTER_KEY_PATH = path.join(CERT_DIR, "nfm-master.key");

// DPAPI wrapping marker: on win32 the key file holds base64 DPAPI-protected bytes,
// prefixed so a future read can tell a DPAPI-wrapped key from a raw one (e.g. a key
// file copied from a non-win32 install). On non-win32 the file holds raw key bytes
// (mode 0o600).
const DPAPI_PREFIX = "dpapi:";

function warn(msg: string, err?: unknown): void {
  // Match server.ts's plain console logging; never throw out of here.
  const detail = err instanceof Error ? err.message : err ? String(err) : "";
  console.warn(`[secretStore] ${msg}${detail ? `: ${detail}` : ""}`);
}

// ── DPAPI (Windows CurrentUser scope) via PowerShell ──────────────────────────────
// We shell out to ProtectedData::Protect/Unprotect, passing base64 in and reading
// base64 out, so the random key bytes survive the stdio round-trip intact. CurrentUser
// scope ties the wrapped key to the panel's Windows user account, which is exactly the
// local-user isolation we want.

function runPowerShell(script: string, inputB64: string): string | null {
  try {
    const res = spawnSync(
      "powershell.exe",
      ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script],
      { input: inputB64, encoding: "utf8", windowsHide: true, timeout: 15000 },
    );
    if (res.error) {
      warn("PowerShell invocation failed", res.error);
      return null;
    }
    if (res.status !== 0) {
      warn(`PowerShell exited with status ${res.status}`, (res.stderr || "").trim());
      return null;
    }
    const out = (res.stdout || "").trim();
    return out.length ? out : null;
  } catch (err) {
    warn("PowerShell spawn threw", err);
    return null;
  }
}

// Wrap raw key bytes with DPAPI; returns base64 of the protected blob, or null on failure.
function dpapiProtect(raw: Buffer): string | null {
  // Read stdin (base64), unprotect→protect, emit base64. Reading from stdin avoids
  // putting key material on the command line (visible in the process list).
  const script =
    "$ErrorActionPreference='Stop';" +
    "Add-Type -AssemblyName System.Security;" +
    "$b=[Console]::In.ReadToEnd().Trim();" +
    "$bytes=[Convert]::FromBase64String($b);" +
    "$prot=[System.Security.Cryptography.ProtectedData]::Protect($bytes,$null,[System.Security.Cryptography.DataProtectionScope]::CurrentUser);" +
    "[Console]::Out.Write([Convert]::ToBase64String($prot));";
  const out = runPowerShell(script, raw.toString("base64"));
  return out;
}

// Reverse of dpapiProtect; returns the raw key bytes, or null on failure.
function dpapiUnprotect(protectedB64: string): Buffer | null {
  const script =
    "$ErrorActionPreference='Stop';" +
    "Add-Type -AssemblyName System.Security;" +
    "$b=[Console]::In.ReadToEnd().Trim();" +
    "$bytes=[Convert]::FromBase64String($b);" +
    "$plain=[System.Security.Cryptography.ProtectedData]::Unprotect($bytes,$null,[System.Security.Cryptography.DataProtectionScope]::CurrentUser);" +
    "[Console]::Out.Write([Convert]::ToBase64String($plain));";
  const out = runPowerShell(script, protectedB64);
  if (!out) return null;
  try {
    const raw = Buffer.from(out, "base64");
    return raw.length === KEY_LEN ? raw : null;
  } catch (err) {
    warn("Failed to decode DPAPI-unprotected key", err);
    return null;
  }
}

// ── Master key lifecycle ──────────────────────────────────────────────────────────

// Cache the loaded key for the process lifetime. `undefined` = not yet attempted;
// `null` = attempted and unavailable (so we stop retrying PowerShell on every call).
let cachedKey: Buffer | null | undefined = undefined;

function isWin32(): boolean {
  return process.platform === "win32";
}

// Persist a freshly generated raw key, DPAPI-wrapped on win32, mode 0o600 elsewhere.
// Returns true on success.
function writeMasterKey(raw: Buffer): boolean {
  try {
    fs.mkdirSync(CERT_DIR, { recursive: true });
  } catch (err) {
    warn("Could not create certs/ dir for master key", err);
    return false;
  }

  if (isWin32()) {
    const protectedB64 = dpapiProtect(raw);
    if (!protectedB64) {
      // DPAPI unavailable — do NOT silently store the key in plaintext on disk; that
      // would defeat the whole point. Caller falls back to plaintext passthrough.
      return false;
    }
    try {
      fs.writeFileSync(MASTER_KEY_PATH, DPAPI_PREFIX + protectedB64, { encoding: "utf8" });
      return true;
    } catch (err) {
      warn("Could not write DPAPI-wrapped master key", err);
      return false;
    }
  }

  // Non-win32: raw bytes, restrictive permissions.
  try {
    fs.writeFileSync(MASTER_KEY_PATH, raw, { mode: 0o600 });
    try {
      fs.chmodSync(MASTER_KEY_PATH, 0o600); // belt-and-suspenders if umask widened it
    } catch {
      /* non-fatal */
    }
    return true;
  } catch (err) {
    warn("Could not write master key", err);
    return false;
  }
}

// Read + unwrap the on-disk master key. Returns the raw key or null if absent/corrupt.
function readMasterKey(): Buffer | null {
  let data: Buffer;
  try {
    if (!fs.existsSync(MASTER_KEY_PATH)) return null;
    data = fs.readFileSync(MASTER_KEY_PATH);
  } catch (err) {
    warn("Could not read master key file", err);
    return null;
  }

  const asText = data.toString("utf8");
  if (asText.startsWith(DPAPI_PREFIX)) {
    // DPAPI-wrapped (typically a win32 install). Unprotect via PowerShell.
    return dpapiUnprotect(asText.slice(DPAPI_PREFIX.length).trim());
  }

  // Raw key bytes (non-win32 install, or a key file shared across OSes).
  if (data.length === KEY_LEN) return data;

  warn(`Master key file has unexpected length ${data.length}`);
  return null;
}

// Lazily load (or create on first use) the master key. Returns null when encryption is
// unavailable on this host — callers MUST treat null as "fall back to plaintext".
function getMasterKey(): Buffer | null {
  if (cachedKey !== undefined) return cachedKey;

  const existing = readMasterKey();
  if (existing) {
    cachedKey = existing;
    return cachedKey;
  }

  // First use: generate a fresh random key and try to persist it.
  const fresh = crypto.randomBytes(KEY_LEN);
  if (writeMasterKey(fresh)) {
    cachedKey = fresh;
    return cachedKey;
  }

  // Could not persist (e.g. DPAPI unavailable or unwritable dir). Mark unavailable so we
  // don't retry on every call, and let callers fall back to plaintext passthrough.
  warn("Encryption unavailable; secrets will be stored as plaintext (backward-compatible)");
  cachedKey = null;
  return null;
}

// ── Public API ──────────────────────────────────────────────────────────────────

/**
 * True iff `value` is one of our tagged ciphertext tokens.
 */
export function isEncrypted(value: string): boolean {
  return typeof value === "string" && value.startsWith(TOKEN_PREFIX);
}

/**
 * Encrypt a plaintext secret, returning a tagged token "nfmenc:v1:<base64(iv|tag|ct)>".
 *
 * Robustness: never throws in a way that loses data. If encryption is unavailable, or
 * anything goes wrong, the PLAINTEXT is returned unchanged so the caller still persists
 * a usable value (backward-compatible with existing plaintext configs). An already
 * encrypted value is returned as-is (idempotent — avoids double-wrapping).
 */
export function encryptSecret(plain: string): string {
  if (typeof plain !== "string" || plain.length === 0) return plain;
  if (isEncrypted(plain)) return plain; // already a token; don't re-wrap

  try {
    const key = getMasterKey();
    if (!key) return plain; // encryption unavailable → plaintext passthrough

    const iv = crypto.randomBytes(IV_LEN);
    const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
    const ct = Buffer.concat([cipher.update(plain, "utf8"), cipher.final()]);
    const tag = cipher.getAuthTag(); // TAG_LEN bytes
    const packed = Buffer.concat([iv, tag, ct]); // iv | tag | ciphertext
    return TOKEN_PREFIX + packed.toString("base64");
  } catch (err) {
    // Hard failure: never lose the secret — return it unchanged.
    warn("encryptSecret failed; storing plaintext", err);
    return plain;
  }
}

/**
 * Decrypt a tagged token back to plaintext. If `value` is NOT one of our tokens it is
 * returned unchanged (backward-compat for existing plaintext configs). If a token can't
 * be decrypted (missing/wrong key, corruption) the original value is returned unchanged
 * rather than throwing — never lock the user out.
 */
export function decryptSecret(value: string): string {
  if (typeof value !== "string" || !isEncrypted(value)) return value;

  try {
    const key = getMasterKey();
    if (!key) {
      warn("decryptSecret: master key unavailable; returning token unchanged");
      return value;
    }

    const packed = Buffer.from(value.slice(TOKEN_PREFIX.length), "base64");
    if (packed.length < IV_LEN + TAG_LEN) {
      warn("decryptSecret: token too short; returning unchanged");
      return value;
    }
    const iv = packed.subarray(0, IV_LEN);
    const tag = packed.subarray(IV_LEN, IV_LEN + TAG_LEN);
    const ct = packed.subarray(IV_LEN + TAG_LEN);

    const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
    decipher.setAuthTag(tag);
    const plain = Buffer.concat([decipher.update(ct), decipher.final()]);
    return plain.toString("utf8");
  } catch (err) {
    // Decryption failed (wrong key after key loss, corruption, …). Return the token
    // unchanged so the rest of the config still loads.
    warn("decryptSecret failed; returning value unchanged", err);
    return value;
  }
}

/**
 * Lock a freshly-written secret file down to the current user on Windows (SEC H1).
 *
 * `chmod 0o600` is a no-op on Windows, so if DPAPI is unavailable and encryptSecret() falls back to
 * plaintext, the SSH key / agent secret would otherwise sit readable by every local user — the exact
 * threat this module exists to prevent. Apply a restrictive ACL (remove inherited ACEs, grant only
 * the current user) so local-user isolation holds even when encryption can't. No-op on POSIX, where
 * the 0o600 mode at write time already suffices. Best-effort: never throws.
 */
export function hardenSecretFileWindows(file: string): void {
  if (process.platform !== "win32") return;
  const user = process.env.USERNAME;
  if (!user) return;
  try {
    // /inheritance:r removes all inherited ACEs; /grant:r <user>:F then leaves ONLY the current user.
    spawnSync("icacls", [file, "/inheritance:r", "/grant:r", `${user}:F`], { timeout: 10000, windowsHide: true });
  } catch { /* best-effort hardening — leaving the 0o600 (no-op on win) is the prior behavior */ }
}

// ── Module-load self-test ─────────────────────────────────────────────────────────
// Best-effort sanity check that the round-trip works on this host. Purely diagnostic;
// must never throw (so importing this module can't crash the server).
try {
  const probe = "nfm-selftest";
  const enc = encryptSecret(probe);
  if (isEncrypted(enc) && decryptSecret(enc) !== probe) {
    warn("self-test round-trip mismatch; encryption may be degraded");
  }
} catch (err) {
  warn("self-test threw", err);
}
