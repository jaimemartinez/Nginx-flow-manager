/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Salted, iterated Apache MD5 (`$apr1$`) password hashing for htpasswd files — the format
 * `htpasswd -m` produces and nginx's `auth_basic_user_file` accepts. Implemented in pure TS
 * (Web Crypto has no MD5) so the panel can hash credentials client-side, with NO CLI and without
 * sending the plaintext password to the server. apr1 salts and iterates 1000×, so it is vastly
 * stronger than the previous unsalted `{SHA}` (plain SHA-1) scheme. Existing `{SHA}` entries keep
 * working — nginx accepts a mix in one file — so this only changes newly-added users.
 */

// ── MD5 (RFC 1321) — operates on bytes, returns a 16-byte digest. ─────────────
const MD5_S = [
  7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
  5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
  4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
  6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];
const MD5_K = (() => {
  const k = new Int32Array(64);
  for (let i = 0; i < 64; i++) k[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 4294967296) | 0;
  return k;
})();

function rotl(x: number, c: number): number {
  return (x << c) | (x >>> (32 - c));
}

export function md5(input: Uint8Array): Uint8Array {
  const origLen = input.length;
  let padded = origLen + 1;
  while (padded % 64 !== 56) padded++;
  const msg = new Uint8Array(padded + 8);
  msg.set(input);
  msg[origLen] = 0x80;
  const bitLen = origLen * 8;
  const dv = new DataView(msg.buffer);
  dv.setUint32(padded, bitLen >>> 0, true);
  dv.setUint32(padded + 4, Math.floor(bitLen / 4294967296) >>> 0, true);

  let a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
  const M = new Int32Array(16);
  for (let off = 0; off < msg.length; off += 64) {
    for (let i = 0; i < 16; i++) M[i] = dv.getUint32(off + i * 4, true) | 0;
    let A = a0, B = b0, C = c0, D = d0;
    for (let i = 0; i < 64; i++) {
      let F: number, g: number;
      if (i < 16) { F = (B & C) | (~B & D); g = i; }
      else if (i < 32) { F = (D & B) | (~D & C); g = (5 * i + 1) % 16; }
      else if (i < 48) { F = B ^ C ^ D; g = (3 * i + 5) % 16; }
      else { F = C ^ (B | ~D); g = (7 * i) % 16; }
      F = (F + A + MD5_K[i] + M[g]) | 0;
      A = D; D = C; C = B;
      B = (B + rotl(F, MD5_S[i])) | 0;
    }
    a0 = (a0 + A) | 0; b0 = (b0 + B) | 0; c0 = (c0 + C) | 0; d0 = (d0 + D) | 0;
  }
  const out = new Uint8Array(16);
  const odv = new DataView(out.buffer);
  odv.setUint32(0, a0 >>> 0, true);
  odv.setUint32(4, b0 >>> 0, true);
  odv.setUint32(8, c0 >>> 0, true);
  odv.setUint32(12, d0 >>> 0, true);
  return out;
}

// ── apr1 ($apr1$) — the Apache flavor of crypt-MD5. ──────────────────────────
const ITOA64 = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
const ENC = new TextEncoder();

function cat(...parts: Uint8Array[]): Uint8Array {
  let len = 0;
  for (const p of parts) len += p.length;
  const out = new Uint8Array(len);
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

function to64(v: number, n: number): string {
  let s = '';
  while (--n >= 0) { s += ITOA64[v & 0x3f]; v >>>= 6; }
  return s;
}

/**
 * Compute the apr1 hash of `password` with the given `salt` (≤ 8 chars from the itoa64 alphabet).
 * Returns the full `$apr1$<salt>$<checksum>` string. Deterministic given (password, salt), so it
 * is verifiable against `openssl passwd -apr1 -salt <salt>` / `htpasswd`.
 */
export function apr1(password: string, salt: string): string {
  const magic = '$apr1$';
  const pw = ENC.encode(password);
  const s = ENC.encode(salt);

  // Alternate digest from password + salt + password.
  let digest = md5(cat(pw, s, pw));

  // Initial context: password + magic + salt, then `password.length` bytes of the alternate digest.
  const ctxParts: Uint8Array[] = [pw, ENC.encode(magic), s];
  for (let pl = pw.length; pl > 0; pl -= 16) ctxParts.push(digest.subarray(0, Math.min(pl, 16)));
  // Then, for each 1-bit of the length, a NUL byte; for each 0-bit, the first password byte.
  for (let i = pw.length; i; i >>>= 1) ctxParts.push(i & 1 ? new Uint8Array([0]) : pw.subarray(0, 1));
  digest = md5(cat(...ctxParts));

  // 1000 rounds of strengthening.
  for (let i = 0; i < 1000; i++) {
    const parts: Uint8Array[] = [];
    parts.push(i & 1 ? pw : digest);
    if (i % 3) parts.push(s);
    if (i % 7) parts.push(pw);
    parts.push(i & 1 ? digest : pw);
    digest = md5(cat(...parts));
  }

  let out = '';
  out += to64((digest[0] << 16) | (digest[6] << 8) | digest[12], 4);
  out += to64((digest[1] << 16) | (digest[7] << 8) | digest[13], 4);
  out += to64((digest[2] << 16) | (digest[8] << 8) | digest[14], 4);
  out += to64((digest[3] << 16) | (digest[9] << 8) | digest[15], 4);
  out += to64((digest[4] << 16) | (digest[10] << 8) | digest[5], 4);
  out += to64(digest[11], 2);
  return `${magic}${salt}$${out}`;
}

/** Generate a random 8-char apr1 salt from the itoa64 alphabet using a CSPRNG. */
export function randomApr1Salt(len = 8): string {
  const bytes = new Uint8Array(len);
  const c: Crypto | undefined = (globalThis as { crypto?: Crypto }).crypto;
  if (c && typeof c.getRandomValues === 'function') c.getRandomValues(bytes);
  else for (let i = 0; i < len; i++) bytes[i] = Math.floor(Math.abs(Math.sin(i + len)) * 256) & 0xff; // non-crypto fallback (tests only)
  let s = '';
  for (let i = 0; i < len; i++) s += ITOA64[bytes[i] & 0x3f];
  return s;
}

/** Hash a password as a fresh salted apr1 entry, ready for an htpasswd file. */
export function htpasswdApr1(password: string): string {
  return apr1(password, randomApr1Salt(8));
}
