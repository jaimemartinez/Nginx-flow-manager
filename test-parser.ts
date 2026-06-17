// Standalone harness copying the pure parser functions from server.ts to inspect the AST.
type NginxToken = { t: 'word' | ';' | '{' | '}'; v: string };
type NginxDirective = { type: 'directive'; name: string; args: string[] };
type NginxBlock     = { type: 'block';     name: string; args: string[]; children: NginxASTNode[] };
type NginxASTNode   = NginxDirective | NginxBlock;

function tokenizeNginx(input: string): NginxToken[] {
  const tokens: NginxToken[] = [];
  let i = 0;
  const len = input.length;
  while (i < len) {
    const ch = input[i];
    if (ch === '#') {
      while (i < len && input[i] !== '\n') i++;
    } else if (/[\s\r\n\t]/.test(ch)) {
      i++;
    } else if (ch === ';') {
      tokens.push({ t: ';', v: ';' }); i++;
    } else if (ch === '{') {
      tokens.push({ t: '{', v: '{' }); i++;
    } else if (ch === '}') {
      tokens.push({ t: '}', v: '}' }); i++;
    } else if (ch === '"' || ch === "'") {
      const q = ch; let word = ''; i++;
      while (i < len && input[i] !== q) {
        if (input[i] === '\\') i++;
        word += input[i++];
      }
      i++;
      tokens.push({ t: 'word', v: word });
    } else {
      let word = '';
      while (i < len && !/[\s\r\n\t;{}"'#]/.test(input[i])) word += input[i++];
      if (word) tokens.push({ t: 'word', v: word });
    }
  }
  return tokens;
}

function parseNginxAST(tokens: NginxToken[]): NginxASTNode[] {
  let pos = 0;
  function parseNodes(): NginxASTNode[] {
    const nodes: NginxASTNode[] = [];
    while (pos < tokens.length && tokens[pos].t !== '}') {
      const tok = tokens[pos];
      if (tok.t !== 'word') { pos++; continue; }
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
        pos++;
        const children = parseNodes();
        if (pos < tokens.length && tokens[pos].t === '}') pos++;
        nodes.push({ type: 'block', name, args, children });
      }
    }
    return nodes;
  }
  return parseNodes();
}

// The exact certbot default config the user pasted (server_name WITHOUT trailing ;)
const config = `
server {
        server_name iglesiaen.com iglesiabaq.org
	root /var/www/html;
	index index.html index.htm index.nginx-debian.html;

	location /.well-known/acme-challenge/ {
        root /var/www/html;
        allow all;
    }

	location / {
		try_files $uri $uri/ =404;
	}

    listen [::]:443 ssl ipv6only=on; # managed by Certbot
    listen 443 ssl; # managed by Certbot
    ssl_certificate /etc/letsencrypt/live/iglesiabaq.org/fullchain.pem; # managed by Certbot
    ssl_certificate_key /etc/letsencrypt/live/iglesiabaq.org/privkey.pem; # managed by Certbot
    include /etc/letsencrypt/options-ssl-nginx.conf; # managed by Certbot
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem; # managed by Certbot
}

server {
    if ($host = iglesiabaq.org) {
        return 301 https://$host$request_uri;
    } # managed by Certbot

	listen 80 default_server;
	listen [::]:80 default_server;
        server_name iglesiaen.com iglesiabaq.org
    return 404; # managed by Certbot
}
`;

const ast = parseNginxAST(tokenizeNginx(config));
console.log(JSON.stringify(ast, null, 2));
