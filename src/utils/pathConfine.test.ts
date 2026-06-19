/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */
import { describe, it, expect } from 'vitest';
import { confinePosixPath, confineNginxPath, SHELL_META_RE } from './pathConfine';
import { shQuote } from '../../ssh-helper';

describe('confinePosixPath — traversal & injection guard', () => {
  const ROOT = '/etc/nginx';

  it('resolves a normal relative path under the root', () => {
    expect(confinePosixPath(ROOT, 'sites-available/app.conf')).toBe('/etc/nginx/sites-available/app.conf');
    expect(confinePosixPath(ROOT, 'conf.d/x.conf')).toBe('/etc/nginx/conf.d/x.conf');
  });

  it('rejects `..` traversal that escapes the root', () => {
    expect(confinePosixPath(ROOT, '../../etc/passwd')).toBeNull();
    expect(confinePosixPath(ROOT, 'sites-available/../../../root/.ssh/authorized_keys')).toBeNull();
  });

  it('rejects an absolute candidate that resolves outside the root', () => {
    expect(confinePosixPath(ROOT, '/etc/passwd')).toBeNull();
  });

  it('rejects the root itself (empty relative)', () => {
    expect(confinePosixPath(ROOT, '.')).toBeNull();
    expect(confinePosixPath(ROOT, '')).toBeNull();
  });

  it('rejects NUL bytes and shell metacharacters', () => {
    expect(confinePosixPath(ROOT, 'a\0b')).toBeNull();
    for (const meta of ['a;b', 'a$(id)', 'a`id`', 'a|b', 'a&b', 'a>b', 'a<b', 'a(b)', 'a{b}', 'a"b', "a'b", 'a\nb']) {
      expect(confinePosixPath(ROOT, meta), meta).toBeNull();
    }
  });
});

describe('confineNginxPath — /etc/nginx confinement mapped onto a real dir', () => {
  it('maps an /etc/nginx/* key under the configured nginx dir', () => {
    expect(confineNginxPath('/etc/nginx/sites-available/a.conf', '/etc/nginx')).toBe('/etc/nginx/sites-available/a.conf');
    // A relocated install: the logical /etc/nginx/* key maps under the real dir.
    expect(confineNginxPath('/etc/nginx/nginx.conf', '/opt/nginx')).toBe('/opt/nginx/nginx.conf');
  });

  it('rejects keys not under /etc/nginx/', () => {
    expect(confineNginxPath('/etc/passwd', '/etc/nginx')).toBeNull();
    expect(confineNginxPath('etc/nginx/x', '/etc/nginx')).toBeNull();
    expect(confineNginxPath('/etc/nginxsomething/x', '/etc/nginx')).toBeNull();
  });

  it('rejects traversal and shell metachars in the key', () => {
    expect(confineNginxPath('/etc/nginx/../../root/x', '/etc/nginx')).toBeNull();
    expect(confineNginxPath('/etc/nginx/$(reboot)', '/etc/nginx')).toBeNull();
  });

  it('SHELL_META_RE matches the dangerous characters it claims to', () => {
    for (const c of ['`', '$', ';', '|', '&', '<', '>', '(', ')', '{', '}', '\n', '\r', '"', "'"]) {
      expect(SHELL_META_RE.test(`x${c}y`), c).toBe(true);
    }
    expect(SHELL_META_RE.test('sites-available/app.conf')).toBe(false);
  });
});

describe('shQuote — POSIX single-quote shell escaping', () => {
  it('wraps a plain value in single quotes', () => {
    expect(shQuote('/etc/nginx')).toBe("'/etc/nginx'");
  });

  it('neutralizes an embedded single quote (no breakout)', () => {
    // The classic injection `'; rm -rf / ;'` must end up fully inside quotes.
    expect(shQuote("a'; rm -rf / ;'b")).toBe("'a'\\''; rm -rf / ;'\\''b'");
  });

  it('leaves $ ` and ; inert inside the single quotes', () => {
    expect(shQuote('$(id);`whoami`')).toBe("'$(id);`whoami`'");
  });
});
