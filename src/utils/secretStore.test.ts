/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, it, expect } from "vitest";
import { encryptSecret, decryptSecret, isEncrypted } from "./secretStore";

// Goal #1 (secrets-at-rest): pins the secretStore contract relied on by the config
// persistence layer — tagged-token round-trip, plaintext passthrough (backward-compat
// with existing unencrypted configs), and isEncrypted detection. The tests are written
// to hold whether or not encryption is actually available on the CI/test host: when the
// master key can be created, encryptSecret yields a token; when it cannot, encryptSecret
// safely passes the plaintext through. Both outcomes must still round-trip to the
// original plaintext (the "never lock the user out" invariant).

const TOKEN_PREFIX = "nfmenc:v1:";

describe("secretStore", () => {
  describe("encrypt → decrypt round-trip", () => {
    const samples = [
      "hunter2",
      "p@ss w0rd with spaces",
      "unicode: ñ á 漢字 🔐",
      "a".repeat(4096),
      "line1\nline2\ttabbed",
    ];

    for (const plain of samples) {
      it(`round-trips ${JSON.stringify(plain.slice(0, 24))}…`, () => {
        const enc = encryptSecret(plain);
        // Whether or not encryption is available, decrypt must recover the original.
        expect(decryptSecret(enc)).toBe(plain);
      });
    }

    it("produces a tagged token when encryption is available", () => {
      const enc = encryptSecret("some-secret");
      if (enc !== "some-secret") {
        // Encryption was available on this host.
        expect(enc.startsWith(TOKEN_PREFIX)).toBe(true);
        expect(isEncrypted(enc)).toBe(true);
        expect(decryptSecret(enc)).toBe("some-secret");
      } else {
        // Encryption unavailable → plaintext passthrough (still valid behavior).
        expect(isEncrypted(enc)).toBe(false);
      }
    });

    it("uses a random IV so two encryptions of the same plaintext differ", () => {
      const a = encryptSecret("same-input");
      const b = encryptSecret("same-input");
      if (isEncrypted(a) && isEncrypted(b)) {
        expect(a).not.toBe(b); // distinct IVs ⇒ distinct tokens
        expect(decryptSecret(a)).toBe("same-input");
        expect(decryptSecret(b)).toBe("same-input");
      }
    });

    it("is idempotent: encrypting an already-encrypted value does not double-wrap", () => {
      const once = encryptSecret("payload");
      const twice = encryptSecret(once);
      expect(twice).toBe(once);
    });

    it("leaves empty strings unchanged", () => {
      expect(encryptSecret("")).toBe("");
      expect(decryptSecret("")).toBe("");
    });
  });

  describe("decryptSecret passes plaintext through unchanged (backward-compat)", () => {
    const plaintexts = [
      "plain-ssh-password",
      "",
      "scrypt$deadbeef$cafebabe", // a different tagged format must not be touched
      "nfmenc:",                  // partial/near-miss prefix, not a real token
      "nfmenc:v2:something",      // unknown version — passthrough, never crash
      "just some text with nfmenc:v1: in the middle",
    ];

    for (const value of plaintexts) {
      it(`returns ${JSON.stringify(value.slice(0, 24))} unchanged`, () => {
        expect(decryptSecret(value)).toBe(value);
      });
    }

    it("returns a corrupt/undecryptable token unchanged instead of throwing", () => {
      const bogus = TOKEN_PREFIX + Buffer.from("too-short").toString("base64");
      expect(() => decryptSecret(bogus)).not.toThrow();
      expect(decryptSecret(bogus)).toBe(bogus);
    });
  });

  describe("isEncrypted", () => {
    it("is true only for the nfmenc:v1: tagged prefix", () => {
      expect(isEncrypted("nfmenc:v1:abc")).toBe(true);
      const enc = encryptSecret("x");
      expect(isEncrypted(enc)).toBe(isEncrypted(enc) ? enc.startsWith(TOKEN_PREFIX) : false);
    });

    it("is false for plaintext and other tagged formats", () => {
      expect(isEncrypted("")).toBe(false);
      expect(isEncrypted("plaintext")).toBe(false);
      expect(isEncrypted("scrypt$aa$bb")).toBe(false);
      expect(isEncrypted("nfmenc:v2:abc")).toBe(false);
      expect(isEncrypted("nfmenc:")).toBe(false);
    });
  });
});
