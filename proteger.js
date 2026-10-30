// Cifra o protótipo com uma senha e gera um index.html seguro para GitHub Pages.
// Uso:  node proteger.js nutricontrol-prototipo.html index.html
// A senha é pedida no terminal (digitação oculta). Também aceita NC_SENHA para testes.
const fs = require("fs");
const crypto = require("crypto");
const readline = require("readline");

const [, , entrada, saida = "index.html"] = process.argv;
if (!entrada) { console.error("Uso: node proteger.js <arquivo.html> [saida.html]"); process.exit(1); }

function pedirSenha() {
  return new Promise((resolve) => {
    if (process.env.NC_SENHA) return resolve(process.env.NC_SENHA);
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: true });
    rl._writeToOutput = (s) => { if (rl.mudo && s.trim() !== "") rl.output.write("*"); else rl.output.write(s); };
    rl.question("Senha de acesso (mín. 10 caracteres): ", (v) => { rl.close(); console.log(); resolve(v); });
    rl.mudo = true;
  });
}

(async () => {
  const senha = await pedirSenha();
  if (senha.length < 10) { console.error("Senha curta demais. Use pelo menos 10 caracteres, de preferência uma frase."); process.exit(1); }

  // página completa que será cifrada (inclui o reset que o hospedeiro do artefato fazia)
  const miolo = fs.readFileSync(entrada, "utf8");
  const pagina = '<!doctype html><html lang="pt-BR"><head><meta charset="utf-8">' +
    '<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">' +
    '<meta name="robots" content="noindex,nofollow">' +
    '<style>:root{color-scheme:light}body{margin:0;font-size:14px}img{max-width:100%}[hidden]{display:none!important}</style>' +
    miolo;

  const salt = crypto.randomBytes(16), iv = crypto.randomBytes(12);
  const chave = crypto.pbkdf2Sync(senha, salt, 600000, 32, "sha256");
  const c = crypto.createCipheriv("aes-256-gcm", chave, iv);
  const ct = Buffer.concat([c.update(pagina, "utf8"), c.final()]);
  const carga = Buffer.concat([salt, iv, ct, c.getAuthTag()]).toString("base64");

  const loader = `<!doctype html>
<html lang="pt-BR"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>Acesso restrito</title>
<style>
:root{--bg:#FAF8FB;--card:#fff;--ink:#1E1A24;--muted:#5A5463;--line:#E6E2EA;--brand:#683D75;color-scheme:light dark}
@media (prefers-color-scheme:dark){:root{--bg:#161118;--card:#211A27;--ink:#F2EDF5;--muted:#B8ADC0;--line:#382E41}}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:grid;place-items:center;background:var(--bg);color:var(--ink);font-family:system-ui,-apple-system,"Segoe UI",sans-serif;padding:16px}
form{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:32px;width:100%;max-width:380px;display:grid;gap:16px}
h1{margin:0;font-size:22px}
p{margin:0;color:var(--muted);font-size:14px}
input{font:inherit;padding:12px 14px;border:1px solid var(--line);border-radius:10px;background:var(--bg);color:var(--ink);width:100%}
input:focus-visible,button:focus-visible{outline:3px solid #4BB3C2;outline-offset:2px}
button{font:inherit;font-weight:700;padding:12px;border:0;border-radius:10px;background:var(--brand);color:#fff;cursor:pointer}
button[disabled]{opacity:.6;cursor:wait}
#erro{color:#E5484D;font-size:14px;min-height:20px}
</style></head><body>
<form id="f" autocomplete="off">
  <div><h1>Acesso restrito</h1><p>Digite a senha para ver o protótipo.</p></div>
  <label for="senha" style="position:absolute;left:-9999px">Senha</label>
  <input id="senha" type="password" placeholder="Senha" autocomplete="off" required autofocus>
  <button id="b" type="submit">Entrar</button>
  <div id="erro" role="alert"></div>
</form>
<script>
const P="${carga}";
async function abrir(senha){
  const raw=Uint8Array.from(atob(P),c=>c.charCodeAt(0));
  const salt=raw.slice(0,16),iv=raw.slice(16,28),ct=raw.slice(28);
  const km=await crypto.subtle.importKey("raw",new TextEncoder().encode(senha),"PBKDF2",false,["deriveKey"]);
  const key=await crypto.subtle.deriveKey({name:"PBKDF2",salt,iterations:600000,hash:"SHA-256"},km,{name:"AES-GCM",length:256},false,["decrypt"]);
  return new TextDecoder().decode(await crypto.subtle.decrypt({name:"AES-GCM",iv},key,ct));
}
document.getElementById("f").addEventListener("submit",async e=>{
  e.preventDefault();
  const b=document.getElementById("b"),er=document.getElementById("erro");
  er.textContent="";b.disabled=true;b.textContent="Abrindo...";
  try{
    const html=await abrir(document.getElementById("senha").value);
    document.open();document.write(html);document.close();
  }catch(_){
    er.textContent="Senha incorreta.";b.disabled=false;b.textContent="Entrar";
    document.getElementById("senha").select();
  }
});
</script></body></html>`;
  fs.writeFileSync(saida, loader);
  console.log("Gerado:", saida, "(" + Math.round(loader.length / 1024) + " KB). Publique só este arquivo.");
})();
