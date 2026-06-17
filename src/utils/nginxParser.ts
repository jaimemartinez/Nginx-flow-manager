// Pure nginx config tokenizer + AST parser, extracted verbatim from server.ts (FIX #3) so the
// parser↔compiler logic lives in one place and can be unit-tested without booting the Express
// server. Behavior is byte-identical to the previous inline definitions.
//
// Tokens carry source offsets so blocks can record the span of their body in the original
// text. This lets us reproduce unrecognized blocks (e.g. lua/perl/njs code, custom config)
// verbatim — including comments — instead of re-serializing a mangled AST.
export type NginxToken = { t: 'word' | ';' | '{' | '}'; v: string; start: number; end: number };
export type NginxDirective = { type: 'directive'; name: string; args: string[] };
export type NginxBlock     = { type: 'block'; name: string; args: string[]; children: NginxASTNode[]; start?: number; end?: number; bodyStart?: number; bodyEnd?: number };
export type NginxASTNode   = NginxDirective | NginxBlock;

export function tokenizeNginx(input: string, comments?: { start: number; end: number; v: string }[]): NginxToken[] {
  const tokens: NginxToken[] = [];
  let i = 0;
  const len = input.length;
  while (i < len) {
    const ch = input[i];
    if (ch === '#') {
      const s = i;
      while (i < len && input[i] !== '\n') i++;
      if (comments) comments.push({ start: s, end: i, v: input.slice(s, i).trimEnd() });
    } else if (/[\s\r\n\t]/.test(ch)) {
      i++;
    } else if (ch === ';') {
      tokens.push({ t: ';', v: ';', start: i, end: i + 1 }); i++;
    } else if (ch === '{') {
      tokens.push({ t: '{', v: '{', start: i, end: i + 1 }); i++;
    } else if (ch === '}') {
      tokens.push({ t: '}', v: '}', start: i, end: i + 1 }); i++;
    } else if (ch === '"' || ch === "'") {
      const q = ch; let word = ''; const s = i; i++;
      while (i < len && input[i] !== q) {
        if (input[i] === '\\') i++;
        word += input[i++];
      }
      i++;
      tokens.push({ t: 'word', v: word, start: s, end: i });
    } else {
      const s = i; let word = '';
      while (i < len && !/[\s\r\n\t;{}"'#]/.test(input[i])) word += input[i++];
      if (word) tokens.push({ t: 'word', v: word, start: s, end: i });
    }
  }
  return tokens;
}

export function parseNginxAST(tokens: NginxToken[], inputLen = 0): NginxASTNode[] {
  let pos = 0;
  function parseNodes(): NginxASTNode[] {
    const nodes: NginxASTNode[] = [];
    while (pos < tokens.length && tokens[pos].t !== '}') {
      const tok = tokens[pos];
      if (tok.t !== 'word') { pos++; continue; }
      const nameStart = tok.start;
      const name = tok.v; pos++;
      const args: string[] = [];
      while (pos < tokens.length && tokens[pos].t === 'word') {
        args.push(tokens[pos].v); pos++;
      }
      if (pos >= tokens.length) break;
      if (tokens[pos].t === ';') {
        pos++;
        nodes.push({ type: 'directive', name, args });
      } else if (tokens[pos].t === '{') {
        const bodyStart = tokens[pos].end; // char right after '{'
        pos++;
        const children = parseNodes();
        const closeTok = pos < tokens.length ? tokens[pos] : undefined;
        const bodyEnd = closeTok ? closeTok.start : inputLen; // char of matching '}'
        const nodeEnd = closeTok ? closeTok.end : inputLen;
        if (closeTok) pos++;
        nodes.push({ type: 'block', name, args, children, start: nameStart, end: nodeEnd, bodyStart, bodyEnd });
      }
    }
    return nodes;
  }
  return parseNodes();
}
