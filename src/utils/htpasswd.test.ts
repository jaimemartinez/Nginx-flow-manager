/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */
import { describe, it, expect } from 'vitest';
import { md5, apr1, randomApr1Salt, htpasswdApr1 } from './htpasswd';

function md5hex(s: string): string {
  return Array.from(md5(new TextEncoder().encode(s))).map((b) => b.toString(16).padStart(2, '0')).join('');
}

describe('md5 (RFC 1321 test vectors)', () => {
  it('matches the canonical digests', () => {
    expect(md5hex('')).toBe('d41d8cd98f00b204e9800998ecf8427e');
    expect(md5hex('abc')).toBe('900150983cd24fb0d6963f7d28e17f72');
    expect(md5hex('The quick brown fox jumps over the lazy dog')).toBe('9e107d9d372bb6826bd81d3542a419d6');
    // > 64-byte input exercises multi-block padding (verified via `openssl dgst -md5`).
    expect(md5hex('a'.repeat(80))).toBe('b15af9cdabbaea0516866a33d8fd0f98');
  });
});

describe('apr1 ($apr1$) — verified against `openssl passwd -apr1`', () => {
  it('matches openssl ground-truth vectors (fixed salt)', () => {
    // openssl passwd -apr1 -salt SbiZ9PvX correct-horse-staple
    expect(apr1('correct-horse-staple', 'SbiZ9PvX')).toBe('$apr1$SbiZ9PvX$kZAs88LQRvbKqe3hBNUl2.');
    // openssl passwd -apr1 -salt abcdefgh password
    expect(apr1('password', 'abcdefgh')).toBe('$apr1$abcdefgh$FBwExRW4dCc8aL.OvjpIE1');
  });

  it('produces the $apr1$<salt>$<hash> shape with a random salt', () => {
    const h = htpasswdApr1('hunter2');
    expect(h).toMatch(/^\$apr1\$[./0-9A-Za-z]{8}\$[./0-9A-Za-z]{22}$/);
  });

  it('is deterministic for a given salt and verifiable by re-hashing', () => {
    const salt = randomApr1Salt(8);
    expect(apr1('s3cret', salt)).toBe(apr1('s3cret', salt));
    // The salt embedded in the output reproduces the same hash.
    const full = htpasswdApr1('s3cret');
    const embeddedSalt = full.split('$')[2];
    expect(apr1('s3cret', embeddedSalt)).toBe(full);
  });

  it('different passwords/salts diverge', () => {
    expect(apr1('a', 'abcdefgh')).not.toBe(apr1('b', 'abcdefgh'));
    expect(apr1('a', 'abcdefgh')).not.toBe(apr1('a', 'hgfedcba'));
  });
});
