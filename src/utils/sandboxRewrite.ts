// FIX #5: AST-aware path rewriting for the validation sandboxes.
//
// The three validation sandboxes (server.ts local, server.ts remote-SSH, agent/src/ops.ts) used a
// blunt `content.replace(/\/etc\/nginx\//g, sandbox)` to point `nginx -t` at sandbox copies of the
// config. That global string replace also rewrites the prefix when it appears INSIDE a quoted
// string literal — e.g. `return 200 "...etc/nginx...";`, a `log_format` template, or an
// `add_header X "/etc/nginx/y";` — so nginx ends up validating a DIFFERENT string than the one that
// is actually deployed. This module replaces that blunt approach with a surgical, AST-aware rewrite
// that only touches the VALUE argument of path-bearing directives, leaving every other byte
// identical (including comments, whitespace, and unrelated string literals).
//
// Strategy: tokenize + parse with ./nginxParser (the same tokenizer/AST the compiler uses, so we
// stay parser↔compiler faithful), walk the directives, and for each path-bearing argument splice a
// replacement substring into the original text using the parser's source spans. We never
// re-serialize the AST — we only overwrite the exact byte ranges of the arguments we mean to
// change, so nothing else can drift.

import { tokenizeNginx, parseNginxAST, type NginxToken } from "./nginxParser";

// Path-bearing directives whose (relevant) argument is a filesystem path that must be rewritten so
// it resolves inside the sandbox. The number is which argument index carries the path (0-based,
// relative to the directive name). access_log/error_log only rewrite their FIRST arg (the target);
// subsequent args are levels/format names, not paths.
const PATH_ARG_INDEX: Record<string, number> = {
  include: 0,
  root: 0,
  alias: 0,
  ssl_certificate: 0,
  ssl_certificate_key: 0,
  ssl_trusted_certificate: 0,
  ssl_dhparam: 0,
  auth_basic_user_file: 0,
  access_log: 0,
  error_log: 0,
  pid: 0,
  client_body_temp_path: 0,
  load_module: 0,
};

// fastcgi_pass / proxy_pass carry a path ONLY when they point at a unix socket ("unix:/path:..."),
// and even then we only rewrite when that socket path lives under realDir. A `proxy_pass
// http://host/etc/nginx/...` URL must NEVER be rewritten. Handled specially below.
const UNIX_SOCKET_DIRECTIVES = new Set(["fastcgi_pass", "proxy_pass"]);

// Directives that are explicitly NOT path-bearing even though their value can legitimately contain
// the realDir substring inside a string literal. Listed for documentation / intent; the default
// behaviour (anything not in PATH_ARG_INDEX / UNIX_SOCKET_DIRECTIVES is left untouched) already
// covers these, so this set is not consulted — it just records the cases the tests pin down.
// e.g. return, add_header, log_format, sub_filter, sub_filter_*.

// A single planned edit: overwrite the byte range [start, end) of the original text with `replacement`.
type Edit = { start: number; end: number; replacement: string };

/**
 * AST-aware replacement of the `realDir` path prefix with `sandboxDir`, applied ONLY to the value
 * of path-bearing directives (never inside quoted string literals or non-path directives).
 *
 * realDir / sandboxDir are matched/rewritten as prefixes. realDir is normalized so a trailing slash
 * is optional in the caller's argument; we match `realDir` followed by a `/` or end-of-arg, exactly
 * mirroring the old `"/etc/nginx/"` prefix semantics.
 */
export function rewriteSandboxPaths(content: string, realDir: string, sandboxDir: string): string {
  const real = realDir.replace(/\/+$/, ""); // strip trailing slash(es); we re-add boundary below
  const sandbox = sandboxDir.replace(/\/+$/, "");
  if (!real) return content;

  // Tokenize WITH comment capture diverted to a throwaway array so comment ranges never become
  // tokens (matching how the rest of the codebase tokenizes). We only need argument spans here.
  const comments: { start: number; end: number; v: string }[] = [];
  const tokens = tokenizeNginx(content, comments);
  const ast = parseNginxAST(tokens, content.length);

  // The AST drops source spans for non-block directives (NginxDirective has no start/end), so to
  // splice argument substrings we re-walk the token stream in lockstep: every directive/block is
  // `word (word)* (';' | '{' … '}')`, exactly as parseNodes() consumes it. We reproduce that scan
  // here purely to recover each argument token's [start,end) span. Keeping the walk identical to
  // the parser guarantees we classify the same tokens as arguments that the parser does.
  const edits: Edit[] = [];
  scanTokens(tokens, content, real, sandbox, edits);
  // (ast is parsed above as a fidelity self-check that the content is well-formed nginx; the
  // token-level scan is what produces the edits. Reference it so it isn't dead.)
  void ast;

  return applyEdits(content, edits);
}

// Walk tokens recognizing directive boundaries and collect rewrite edits for path-bearing args.
function scanTokens(
  tokens: NginxToken[],
  content: string,
  real: string,
  sandbox: string,
  edits: Edit[],
): void {
  let pos = 0;
  while (pos < tokens.length) {
    const tok = tokens[pos];
    if (tok.t === "}") { pos++; continue; }
    if (tok.t === ";") { pos++; continue; }
    if (tok.t === "{") { pos++; continue; }
    if (tok.t !== "word") { pos++; continue; }

    // Start of a directive/block: name then a run of word args, terminated by ';' or '{'.
    const name = tok.v;
    pos++;
    const argTokens: NginxToken[] = [];
    while (pos < tokens.length && tokens[pos].t === "word") {
      argTokens.push(tokens[pos]);
      pos++;
    }
    // pos now sits on ';' or '{' (or EOF); the outer loop will advance past it.

    planDirectiveEdits(name, argTokens, content, real, sandbox, edits);
  }
}

function planDirectiveEdits(
  name: string,
  argTokens: NginxToken[],
  content: string,
  real: string,
  sandbox: string,
  edits: Edit[],
): void {
  if (argTokens.length === 0) return;

  if (name in PATH_ARG_INDEX) {
    const idx = PATH_ARG_INDEX[name];
    const t = argTokens[idx];
    if (t) planPrefixEdit(t, content, real, sandbox, edits, /*requireUnixPrefix*/ false);
    return;
  }

  if (UNIX_SOCKET_DIRECTIVES.has(name)) {
    // Only the FIRST arg can be the upstream; rewrite ONLY when it is `unix:<realDir...>`.
    const t = argTokens[0];
    if (t) planPrefixEdit(t, content, real, sandbox, edits, /*requireUnixPrefix*/ true);
    return;
  }

  // Any other directive (return, add_header, log_format, sub_filter, proxy_set_header, …) is left
  // byte-identical even if an argument contains the realDir substring inside a string literal.
}

// Splice the realDir→sandbox prefix replacement into a single argument token's source span.
//
// The token's [start,end) covers the RAW text of the argument in `content`, including surrounding
// quotes for quoted words. We must therefore look at the raw slice (not the parser's unquoted `v`)
// so we preserve quoting and only ever touch a genuine path argument. We deliberately do NOT
// rewrite a path that appears inside a quoted argument here either — a quoted path argument is
// still a path argument of a path-bearing directive (e.g. `root "/etc/nginx/ht ml";`), so it is
// legitimate to rewrite; the protection is that we only rewrite path-bearing DIRECTIVES, and within
// them we rewrite the path content whether quoted or not.
function planPrefixEdit(
  tok: NginxToken,
  content: string,
  real: string,
  sandbox: string,
  edits: Edit[],
  requireUnixPrefix: boolean,
): void {
  const raw = content.slice(tok.start, tok.end);

  // Determine the quote char (if the raw arg is quoted) and the inner value offset.
  let quote = "";
  let inner = raw;
  if ((raw.startsWith('"') && raw.endsWith('"') && raw.length >= 2) ||
      (raw.startsWith("'") && raw.endsWith("'") && raw.length >= 2)) {
    quote = raw[0];
    inner = raw.slice(1, -1);
  }

  let prefix = "";
  let pathPart = inner;
  if (requireUnixPrefix) {
    if (!inner.startsWith("unix:")) return; // a TCP/URL upstream — never a sandbox path
    prefix = "unix:";
    pathPart = inner.slice("unix:".length);
  }

  // Match realDir as a prefix, with the boundary being a '/' or the end of the path part — mirrors
  // the old `"/etc/nginx/"` literal-prefix replacement. We must not rewrite e.g. "/etc/nginxlol".
  if (!matchesDirPrefix(pathPart, real)) return;

  const rewrittenPath = sandbox + pathPart.slice(real.length);
  const newInner = prefix + rewrittenPath;

  // For fastcgi_pass/proxy_pass unix sockets the inner part may carry a `:fragment` after the path
  // (e.g. `unix:/run/php.sock:`); that suffix is preserved verbatim because we only replaced the
  // realDir prefix of pathPart, not its tail.
  const replacement = quote + newInner + quote;
  if (replacement === raw) return; // no-op guard

  // Replace the WHOLE raw token span (incl. any surrounding quotes) with the rebuilt value, so the
  // original quoting style is preserved exactly and nothing outside the argument is touched.
  edits.push({ start: tok.start, end: tok.end, replacement });
}

// True iff `value` begins with `dir` and the next char is '/' or the string ends — i.e. `dir` is a
// genuine path-component prefix, not just a leading substring of a longer name.
function matchesDirPrefix(value: string, dir: string): boolean {
  if (!value.startsWith(dir)) return false;
  if (value.length === dir.length) return true; // exactly the dir
  return value[dir.length] === "/";
}

// Apply non-overlapping edits to the content, right-to-left so earlier offsets stay valid.
function applyEdits(content: string, edits: Edit[]): string {
  if (edits.length === 0) return content;
  const sorted = [...edits].sort((a, b) => a.start - b.start);
  let out = "";
  let cursor = 0;
  for (const e of sorted) {
    if (e.start < cursor) continue; // overlap guard (shouldn't happen — args don't overlap)
    out += content.slice(cursor, e.start);
    out += e.replacement;
    cursor = e.end;
  }
  out += content.slice(cursor);
  return out;
}

/**
 * Neutralize runtime-only directives that make a bare `nginx -t` fail in a sandbox even when the
 * config is valid. Captures the existing pid/error_log redirect + optional `user` comment-out,
 * line-aware, so the three sandboxes can share one implementation.
 *
 *  - `pid`:      redirect to opts.pid       (root-only /run path otherwise → EACCES)
 *  - `errorLog`: redirect the MAIN error_log to opts.errorLog (root-only /var/log path otherwise)
 *  - `commentUser`: comment out the `user` directive (getpwnam fails when run as non-root / no such user)
 *
 * Uses the same line-anchored regexes the original inline sandboxes used, so behaviour is
 * byte-identical to the code it replaces. Only the FIRST occurrence of pid/error_log at column-ish
 * start is what nginx treats as the main context directive; the `/^\s*…;/gm` form matches each on
 * its own line exactly like before.
 */
export function neutralizeRuntimeDirectives(
  content: string,
  opts: { pid?: string; errorLog?: string; commentUser?: boolean },
): string {
  let r = content;
  if (opts.commentUser) {
    r = r.replace(/^\s*user\s+[^;]+;/gm, "# user commented_out_for_sandboxed_validation;");
  }
  if (opts.pid !== undefined) {
    r = r.replace(/^\s*pid\s+[^;]+;/gm, `pid ${opts.pid};`);
  }
  if (opts.errorLog !== undefined) {
    r = r.replace(/^\s*error_log\s+[^;]+;/gm, `error_log ${opts.errorLog};`);
  }
  return r;
}
