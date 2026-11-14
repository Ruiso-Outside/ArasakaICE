// Piphin Escudo no Linux: a mesma ideia do Windows (coleta só de leitura -> achados em linguagem simples -> correção
// com Desfazer -> Vigia), com o que importa no Linux (Zorin, Ubuntu e derivados):
//   invasão   contas com poder de root, chaves SSH, o que abre sozinho (autostart, cron, systemd do usuário, .bashrc),
//             /etc/ld.so.preload, programas rodando de /tmp, hosts desviando sites
//   brechas   firewall (ufw), portas abertas para a rede, servidor SSH, acesso remoto, login automático, atualizações
//   proteção  AppArmor, bloqueio de tela, criptografia do disco, ClamAV (opcional)
// O que precisa de administrador roda junto, com UMA senha (pkexec + linux-helper.py, que só aceita a lista dele).
"use strict";
const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");
const { execFile } = require("child_process");

const HOME = os.homedir();
const CONF = process.env.XDG_CONFIG_HOME || path.join(HOME, ".config");
const read = (f) => { try { return fs.readFileSync(f, "utf8"); } catch { return ""; } };
const exists = (f) => { try { fs.accessSync(f); return true; } catch { return false; } };
const ls = (d) => { try { return fs.readdirSync(d); } catch { return []; } };
const has = (cmd) => process.env.PATH.split(":").some((d) => exists(path.join(d, cmd)));
function run(file, args, { timeout = 60000 } = {}) {
  return new Promise((resolve) => execFile(file, args, { timeout, maxBuffer: 32 * 1024 * 1024, env: { ...process.env, LC_ALL: "C" } }, (err, out, e) =>
    resolve({ code: err ? (typeof err.code === "number" ? err.code : 1) : 0, out: String(out || ""), err: String(e || "") })));
}
const gget = async (schema, key) => { const r = await run("gsettings", ["get", schema, key]); return r.code === 0 ? r.out.trim() : null; };

// comandos que vírus usam para baixar e rodar coisas escondido
const SHADY = /(curl|wget)[^|;&]*\|\s*(ba|z|da)?sh\b|base64\s+(-d|--decode)[^|]*\|\s*(ba|z)?sh|\bnc(at)?\s+(-e|-c)\b|\/dev\/tcp\/|python3?\s+-c\s+['"][^'"]*(socket|exec|base64)|\beval\s+"\$\(|mkfifo\s+\/tmp|\/tmp\/\.|\/dev\/shm\//i;
const TMP = /^\/(tmp|dev\/shm|var\/tmp)\//;
const RISKY_PORTS = { 21: "FTP", 22: "SSH", 23: "Telnet", 139: "Compartilhamento (Samba)", 445: "Compartilhamento (Samba)", 3389: "Área de Trabalho Remota (RDP)", 5900: "VNC", 5901: "VNC",
  5938: "TeamViewer", 3306: "MySQL/MariaDB", 5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB", 2375: "Docker sem senha", 8080: "Servidor web de teste", 11211: "Memcached" };
const BIG_SITES = /(google|gmail|youtube|microsoft|live\.com|outlook|office|facebook|instagram|whatsapp|twitter|x\.com|paypal|mercadopago|mercadolivre|nubank|itau|bradesco|santander|caixa|bb\.com|steam|discord|github|ubuntu|zorin)/i;
const REMOTE = [["teamviewer", "TeamViewer"], ["anydesk", "AnyDesk"], ["rustdesk", "RustDesk"], ["x11vnc", "x11vnc"], ["xrdp", "xrdp (Área de Trabalho Remota)"], ["vino-server", "Vino (compartilhar tela)"], ["gnome-remote-desktop-daemon", "Área de Trabalho Remota do GNOME"]];

// ---------------------------------------------------------------- coleta (só leitura)
function parseDesktop(text) {
  const o = {}; let main = false;
  for (const line of text.split("\n")) {
    if (/^\[/.test(line)) { main = line.trim() === "[Desktop Entry]"; continue; }
    const m = main && /^([\w-]+)=(.*)$/.exec(line.trim());
    if (m && !(m[1] in o)) o[m[1]] = m[2];
  }
  return o;
}
function listening() {
  const out = [];
  for (const [f, v6] of [["/proc/net/tcp", false], ["/proc/net/tcp6", true]]) {
    for (const l of read(f).split("\n").slice(1)) {
      const p = l.trim().split(/\s+/); if (p.length < 4 || p[3] !== "0A") continue;
      const [addr, port] = p[1].split(":");
      const local = v6 ? /^0{24}0100007F$|^0{31}1$/i.test(addr) || /7F$/i.test(addr.slice(-8)) && /FFFF0000/i.test(addr) : /7F$/i.test(addr);
      if (!local) out.push({ port: parseInt(port, 16), any: /^0+$/.test(addr) });
    }
  }
  return [...new Map(out.map((x) => [x.port, x])).values()];
}
function procsFromTmp() {
  const out = [];
  for (const d of ls("/proc")) {
    if (!/^\d+$/.test(d)) continue;
    let exe = ""; try { exe = fs.readlinkSync(`/proc/${d}/exe`).replace(/ \(deleted\)$/, ""); } catch { continue; }
    if (TMP.test(exe)) out.push({ pid: Number(d), exe, name: read(`/proc/${d}/comm`).trim() });
  }
  return out;
}
const running = (name) => ls("/proc").some((d) => /^\d+$/.test(d) && read(`/proc/${d}/comm`).trim() === name.slice(0, 15));

async function collect({ admin = false, light = false } = {}) {
  const raw = { at: new Date().toISOString(), linux: true, admin: false, light };
  // contas
  raw.users = read("/etc/passwd").split("\n").filter(Boolean).map((l) => l.split(":")).map(([name, , uid, gid, , home, shell]) => ({ name, uid: Number(uid), gid: Number(gid), home, shell }))
    .filter((u) => u.uid === 0 || u.uid >= 1000 && u.uid < 65534).map((u) => ({ ...u, enabled: !/nologin|false$/.test(u.shell || "") }));
  const groups = Object.fromEntries(read("/etc/group").split("\n").filter(Boolean).map((l) => l.split(":")).map(([g, , , m]) => [g, (m || "").split(",").filter(Boolean)]));
  raw.admins = [...new Set([...(groups.sudo || []), ...(groups.admin || []), ...(groups.wheel || [])])].map((name) => ({ name }));
  // o que abre sozinho
  raw.autostart = ls(path.join(CONF, "autostart")).filter((f) => f.endsWith(".desktop")).map((f) => {
    const d = parseDesktop(read(path.join(CONF, "autostart", f)));
    return { file: path.join(CONF, "autostart", f), name: d.Name || f, command: d.Exec || "", enabled: d.Hidden !== "true" && d["X-GNOME-Autostart-enabled"] !== "false" };
  });
  const cr = await run("crontab", ["-l"]);
  raw.cron = cr.code === 0 ? cr.out.split("\n").filter((l) => l.trim() && !l.trim().startsWith("#")) : [];
  raw.userUnits = ls(path.join(CONF, "systemd", "user")).filter((f) => /\.(service|timer)$/.test(f)).map((f) => ({ file: path.join(CONF, "systemd", "user", f), name: f, exec: (/^ExecStart=(.*)$/m.exec(read(path.join(CONF, "systemd", "user", f))) || [])[1] || "" }));
  raw.shellrc = [".bashrc", ".profile", ".bash_profile", ".zshrc"].map((f) => path.join(HOME, f)).filter(exists).map((f) => ({ file: f, shady: read(f).split("\n").filter((l) => SHADY.test(l)).slice(0, 5) }));
  raw.systemUnits = ls("/etc/systemd/system").filter((f) => f.endsWith(".service")).map((f) => ({ name: f, exec: (/^ExecStart=(.*)$/m.exec(read(path.join("/etc/systemd/system", f))) || [])[1] || "" }));
  raw.preload = read("/etc/ld.so.preload").trim();
  raw.hosts = read("/etc/hosts").split("\n").map((l) => l.trim()).filter((l) => l && !l.startsWith("#")).filter((l) => !/^(127\.0\.[01]\.1|::1|ff02::|fe00::|127\.0\.1\.1)\s/.test(l));
  raw.sshKeys = read(path.join(HOME, ".ssh", "authorized_keys")).split("\n").filter((l) => /^(ssh-|ecdsa-|sk-)/.test(l.trim())).map((l) => l.trim().split(/\s+/).slice(2).join(" ") || l.trim().slice(0, 30) + "...");
  raw.proxy = { mode: (await gget("org.gnome.system.proxy", "mode")) || "'none'" };
  raw.remote = { installed: REMOTE.filter(([b]) => has(b)).map(([b, n]) => ({ name: n, bin: b })), running: REMOTE.filter(([b]) => running(b)).map(([b, n]) => ({ name: n, bin: b })) };
  if (light) return raw;
  raw.listen = listening();
  raw.fromTmp = procsFromTmp();
  raw.ufw = { installed: has("ufw") || exists("/usr/sbin/ufw"), enabled: /^ENABLED=yes/m.test(read("/etc/ufw/ufw.conf")) };
  const sshd = read("/etc/ssh/sshd_config") + "\n" + ls("/etc/ssh/sshd_config.d").map((f) => read(path.join("/etc/ssh/sshd_config.d", f))).join("\n");
  const sshOpt = (k) => ((new RegExp(`^\\s*${k}\\s+(\\S+)`, "mi").exec(sshd) || [])[1] || "").toLowerCase();
  raw.ssh = { server: exists("/usr/sbin/sshd"), listening: raw.listen.some((x) => x.port === 22), rootLogin: sshOpt("PermitRootLogin"), password: sshOpt("PasswordAuthentication") };
  const upd = read("/var/lib/update-notifier/updates-available");
  raw.updates = { pending: Number((/(\d+) updates? can be applied/.exec(upd) || [])[1]) || 0, security: Number((/(\d+) (of these )?updates? (are|is a) (standard )?security/.exec(upd) || [])[1]) || 0,
    auto: /Unattended-Upgrade\s+"1"/.test(read("/etc/apt/apt.conf.d/20auto-upgrades")), reboot: exists("/var/run/reboot-required") };
  const gdm = read("/etc/gdm3/custom.conf") + read("/etc/gdm3/daemon.conf");
  raw.autologin = { on: /^\s*AutomaticLoginEnable\s*=\s*(true|1)/mi.test(gdm), user: (/^\s*AutomaticLogin\s*=\s*(\S+)/mi.exec(gdm) || [])[1] || "" };
  raw.lock = { enabled: await gget("org.gnome.desktop.screensaver", "lock-enabled"), idle: await gget("org.gnome.desktop.session", "idle-delay") };
  raw.apparmor = read("/sys/module/apparmor/parameters/enabled").trim() === "Y";
  const lsblk = await run("lsblk", ["-rno", "TYPE"]);
  raw.encrypted = /\bcrypt\b/.test(lsblk.out);
  raw.laptop = ls("/sys/class/power_supply").some((b) => /^BAT/.test(b));
  raw.homeMode = (() => { try { return fs.statSync(HOME).mode & 0o777; } catch { return null; } })();
  raw.clamav = has("clamscan");
  if (admin) { // coleta completa: o que só o administrador lê (sudo sem senha, cron do sistema)
    const r = await elevated([{ type: "collect" }]);
    if (r.declined) throw Object.assign(new Error("O pedido de administrador foi recusado"), { declined: true });
    const c = (r.actions || [])[0] || {};
    raw.admin = true;
    raw.nopasswd = c.nopasswd || [];
    raw.rootCron = c.rootCron || [];
  }
  return raw;
}

// ---------------------------------------------------------------- análise
function analyze(d) {
  const F = [], good = [];
  const add = (f) => F.push({ details: [], fix: null, ...f });
  const yes = (t) => good.push(t);
  // invasão
  const roots = (d.users || []).filter((u) => u.uid === 0 && u.name !== "root");
  if (roots.length) add({ id: "uid0", cat: "invasao", sev: "critical", title: "Existe outra conta com poder total (root)", text: "Só a conta root deveria ter o número 0. Uma conta extra com esse poder é um jeito clássico de invasores voltarem ao PC.", details: roots.map((u) => u.name) });
  else yes("Só a conta root tem poder total");
  if (d.preload) add({ id: "preload", cat: "invasao", sev: "critical", title: "Há uma biblioteca forçada em todos os programas (/etc/ld.so.preload)", text: "Esse arquivo faz uma biblioteca carregar dentro de todos os programas. É usado por rootkits para se esconder. Em um PC comum ele não existe.", details: d.preload.split("\n").slice(0, 5) });
  for (const a of d.autostart || []) if (a.enabled && (SHADY.test(a.command) || TMP.test(a.command.split(/\s+/)[0] || ""))) add({ id: "auto:" + a.file, cat: "invasao", sev: "high", title: `"${a.name}" abre sozinho com um comando suspeito`, text: "Ele roda ao entrar na sessão e baixa ou executa algo de um lugar temporário, como fazem os vírus.", details: [a.command.slice(0, 300), a.file], fix: { id: "autostart_off", params: { file: a.file } } });
  const badCron = (d.cron || []).filter((l) => SHADY.test(l) || /\s\/tmp\//.test(l));
  if (badCron.length) add({ id: "cron", cat: "invasao", sev: "high", title: "Tarefa agendada (cron) com comando suspeito", text: "Uma tarefa agendada da sua conta baixa ou roda algo escondido. Confira com \"crontab -e\" no terminal e apague a linha se não foi você.", details: badCron.slice(0, 5) });
  for (const u of d.userUnits || []) if (SHADY.test(u.exec) || TMP.test(u.exec.split(/\s+/)[0] || "")) add({ id: "unit:" + u.name, cat: "invasao", sev: "high", title: `Serviço da sua conta "${u.name}" roda algo suspeito`, text: "Um serviço do systemd da sua conta executa um comando que baixa ou roda coisas de pastas temporárias.", details: [u.exec.slice(0, 300), u.file] });
  for (const s of d.shellrc || []) if (s.shady.length) add({ id: "rc:" + s.file, cat: "invasao", sev: "high", title: `O arquivo ${path.basename(s.file)} roda um comando suspeito`, text: "Toda vez que um terminal abre, esse comando roda. Linhas assim (baixar e executar, conexão reversa) são típicas de invasão.", details: s.shady });
  for (const p of d.fromTmp || []) add({ id: "tmp:" + p.exe, cat: "invasao", sev: "high", title: `Programa rodando de uma pasta temporária: ${p.name}`, text: "Programas normais não rodam de /tmp ou /dev/shm. Vírus costumam se esconder aí.", details: [`${p.exe} (processo ${p.pid})`] });
  const hostBad = (d.hosts || []).filter((l) => BIG_SITES.test(l) && !/^0\.0\.0\.0\s/.test(l));
  if (hostBad.length) add({ id: "hosts", cat: "invasao", sev: "high", title: "O arquivo hosts desvia sites conhecidos", text: "O /etc/hosts manda nomes de sites grandes (banco, Google, Steam...) para outro endereço. Isso pode levar a páginas falsas.", details: hostBad.slice(0, 8) });
  if ((d.sshKeys || []).length) add({ id: "sshkeys", cat: "invasao", sev: d.ssh && d.ssh.listening ? "medium" : "low", title: `${d.sshKeys.length} ${d.sshKeys.length === 1 ? "chave pode" : "chaves podem"} entrar na sua conta por SSH`, text: "Quem tem essas chaves entra no PC sem senha pelo SSH. Se você não reconhece alguma, apague a linha em ~/.ssh/authorized_keys.", details: d.sshKeys.slice(0, 8) });
  for (const n of d.nopasswd || []) add({ id: "nopasswd:" + n, cat: "brecha", sev: "medium", title: "Comando de administrador sem pedir senha", text: "Uma regra do sudo deixa rodar como administrador sem senha. Se não foi você que configurou, pode ser uma porta dos fundos.", details: [n] });
  for (const c of d.rootCron || []) if (SHADY.test(c)) add({ id: "rootcron", cat: "invasao", sev: "critical", title: "Tarefa do sistema (root) com comando suspeito", text: "Uma tarefa agendada do administrador baixa ou executa algo escondido.", details: [c.slice(0, 300)] });
  // brechas
  if (d.ufw) {
    if (!d.ufw.installed) add({ id: "ufw-missing", cat: "brecha", sev: "medium", title: "Sem firewall", text: "O firewall bloqueia conexões de fora que você não pediu. O ufw é o firewall simples do Ubuntu e do Zorin.", fix: { id: "ufw_install", params: {} } });
    else if (!d.ufw.enabled) add({ id: "ufw-off", cat: "brecha", sev: "medium", title: "O firewall está desligado", text: "Ligar o ufw bloqueia as conexões de fora que você não pediu. Jogos, navegador e Steam continuam funcionando.", fix: { id: "ufw_on", params: {} } });
    else yes("Firewall (ufw) ligado");
  }
  for (const p of d.listen || []) {
    const name = RISKY_PORTS[p.port];
    if (!name) continue;
    add({ id: "port:" + p.port, cat: "brecha", sev: [23, 2375, 6379, 11211, 27017].includes(p.port) ? "high" : d.ufw && d.ufw.enabled ? "low" : "medium", title: `Porta ${p.port} aberta para a rede (${name})`,
      text: d.ufw && d.ufw.enabled ? "Um programa espera conexões nessa porta. O firewall está ligado, então só passa se houver uma regra permitindo." : "Um programa espera conexões de outros aparelhos nessa porta. Se você não usa esse serviço, desinstale ou desligue.", details: [`porta ${p.port}${p.any ? " em todos os endereços" : ""}`] });
  }
  if (d.ssh && d.ssh.server && d.ssh.listening) {
    if (d.ssh.rootLogin === "yes") add({ id: "ssh-root", cat: "brecha", sev: "high", title: "O SSH aceita login direto como root", text: "Qualquer um que descubra a senha do root entra com poder total. O normal é entrar com a sua conta e usar sudo.", fix: { id: "ssh_root_off", params: {} } });
    if (d.ssh.password !== "no") add({ id: "ssh-pass", cat: "brecha", sev: "low", title: "O SSH aceita senha", text: "Robôs na internet tentam senhas no SSH o tempo todo. Se você acessa de fora, prefira chaves SSH e desligue a senha (PasswordAuthentication no). Se só usa em casa, tudo bem." });
  }
  for (const r of (d.remote || {}).running || []) add({ id: "remote:" + r.bin, cat: "brecha", sev: "medium", title: `Programa de acesso remoto rodando: ${r.name}`, text: "Ele deixa outra pessoa controlar o PC. Se não foi você que instalou, feche e desinstale: golpistas pedem para instalar esses programas." });
  if (d.autologin && d.autologin.on) add({ id: "autologin", cat: "brecha", sev: d.laptop ? "medium" : "low", title: "Login automático ligado", text: "Quem ligar o PC entra direto na sua conta, sem senha.", fix: { id: "autologin_off", params: {} } });
  if (d.updates) {
    if (d.updates.security) add({ id: "upd-sec", cat: "brecha", sev: "medium", title: `${d.updates.security} ${d.updates.security === 1 ? "atualização de segurança pendente" : "atualizações de segurança pendentes"}`, text: "Atualizações de segurança fecham brechas conhecidas. Abra o Atualizador de Programas (ou rode sudo apt upgrade)." });
    else if (d.updates.pending) add({ id: "upd", cat: "brecha", sev: "low", title: `${d.updates.pending} atualizações pendentes`, text: "Atualize pelo Atualizador de Programas quando puder." });
    else yes("Sistema atualizado");
    if (!d.updates.auto) add({ id: "upd-auto", cat: "brecha", sev: "low", title: "Atualizações de segurança automáticas desligadas", text: "Com elas ligadas, o sistema instala sozinho as correções de segurança.", fix: { id: "unattended_on", params: {} } });
    if (d.updates.reboot) add({ id: "reboot", cat: "protecao", sev: "info", title: "Reinicie para terminar uma atualização", text: "Uma atualização (geralmente do kernel) só vale depois de reiniciar." });
  }
  if (d.proxy && /manual|auto/.test(d.proxy.mode)) add({ id: "proxy", cat: "brecha", sev: "medium", title: "A internet passa por um proxy", text: "Todo o tráfego do navegador passa por outro computador. Se você não configurou isso, pode ser para espionar.", fix: { id: "proxy_off", params: {} } });
  // proteção
  if (d.apparmor === false) add({ id: "apparmor", cat: "protecao", sev: "medium", title: "O AppArmor está desligado", text: "O AppArmor limita o que cada programa pode fazer. No Ubuntu e no Zorin ele vem ligado." });
  else if (d.apparmor) yes("AppArmor ligado");
  if (d.lock && d.lock.enabled === "false") add({ id: "lock", cat: "protecao", sev: "low", title: "A tela não bloqueia sozinha", text: "Se você sair de perto, qualquer um pode usar o PC.", fix: { id: "lock_on", params: {} } });
  if (d.encrypted) yes("Disco criptografado");
  else if (d.laptop) add({ id: "crypt", cat: "protecao", sev: "low", title: "O disco não é criptografado", text: "Se o notebook for roubado, dá para ler os arquivos tirando o disco. A criptografia (LUKS) é escolhida na instalação do sistema." });
  if (d.homeMode != null && (d.homeMode & 0o007)) add({ id: "home", cat: "brecha", sev: "low", title: "Outras contas do PC podem ver a sua pasta pessoal", text: "A pasta pessoal está aberta para leitura de outros usuários deste computador.", fix: { id: "home_private", params: {} } });
  if (d.clamav) yes("ClamAV instalado");
  return { findings: F, good };
}

// ---------------------------------------------------------------- correções (com Desfazer)
const FIXES = {
  ufw_on: { label: "Ligar o firewall", admin: () => true, undo: true },
  ufw_install: { label: "Instalar e ligar o firewall", admin: () => true, undo: false },
  ssh_root_off: { label: "Bloquear o login como root no SSH", admin: () => true, undo: true },
  autologin_off: { label: "Desligar o login automático", admin: () => true, undo: true },
  unattended_on: { label: "Ligar as atualizações automáticas", admin: () => true, undo: true },
  autostart_off: { label: "Tirar da inicialização", admin: () => false, undo: true },
  proxy_off: { label: "Desligar o proxy", admin: () => false, undo: true },
  lock_on: { label: "Ligar o bloqueio de tela", admin: () => false, undo: true },
  home_private: { label: "Fechar a pasta pessoal", admin: () => false, undo: true },
};
async function userFix(x) {
  const p = x.params || {};
  if (x.fix === "autostart_off") {
    const f = x.undo ? x.backup.file : p.file;
    if (!f || !f.startsWith(path.join(CONF, "autostart") + "/")) throw new Error("arquivo inválido");
    if (x.undo) { fs.writeFileSync(f, x.backup.text); return { ok: true, message: "Voltou para a inicialização" }; }
    const text = read(f);
    fs.writeFileSync(f, text.replace(/^X-GNOME-Autostart-enabled=.*\n?/m, "").replace(/(\[Desktop Entry\][^\n]*\n)/, "$1X-GNOME-Autostart-enabled=false\n"));
    return { ok: true, backup: { file: f, text }, message: "Não abre mais sozinho" };
  }
  if (x.fix === "proxy_off" || x.fix === "lock_on") {
    const [schema, key, val] = x.fix === "proxy_off" ? ["org.gnome.system.proxy", "mode", "none"] : ["org.gnome.desktop.screensaver", "lock-enabled", "true"];
    const old = x.undo ? null : await gget(schema, key);
    const r = await run("gsettings", ["set", schema, key, x.undo ? String(x.backup.old).replace(/^'|'$/g, "") : val]);
    if (r.code) throw new Error(r.err.trim() || "gsettings falhou");
    return { ok: true, backup: { old }, message: x.undo ? "Desfeito" : "Pronto" };
  }
  if (x.fix === "home_private") {
    if (x.undo) { fs.chmodSync(HOME, x.backup.mode); return { ok: true, message: "Desfeito" }; }
    const mode = fs.statSync(HOME).mode & 0o777;
    fs.chmodSync(HOME, mode & 0o750);
    return { ok: true, backup: { mode }, message: "Só você vê a sua pasta pessoal" };
  }
  throw new Error("correção desconhecida");
}
async function apply(list) {
  const user = list.filter((x) => !FIXES[x.fix] || !FIXES[x.fix].admin(x.params || {})), adm = list.filter((x) => FIXES[x.fix] && FIXES[x.fix].admin(x.params || {}));
  const results = [];
  for (const x of user) { try { results.push(await userFix(x)); } catch (e) { results.push({ ok: false, message: e.message }); } }
  if (adm.length) {
    const r = await elevated(adm.map((x) => ({ type: "fix", fix: x.fix, undo: !!x.undo, backup: x.backup || null })));
    if (r.declined) results.push(...adm.map(() => ({ ok: false, message: "A senha de administrador foi recusada" })));
    else results.push(...adm.map((_, i) => { const a = (r.actions || [])[i] || {}; return { ok: !!a.ok, backup: a.backup, message: a.ok ? (a.message || "Pronto") : a.error || "Não deu certo" }; }));
  }
  return results;
}

// ajudante de administrador: uma senha (pkexec) para tudo
async function elevated(actions) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "piphin-escudo-"));
  const id = crypto.randomBytes(5).toString("hex"), job = path.join(dir, `job-${id}.json`), out = path.join(dir, `res-${id}.json`);
  fs.writeFileSync(job, JSON.stringify({ actions }));
  const r = await run("pkexec", ["/usr/bin/python3", "-I", path.join(__dirname, "linux-helper.py"), job, out], { timeout: 20 * 60000 });
  try {
    if (!exists(out)) return r.code === 126 || r.code === 127 ? { declined: true } : { ok: false, actions: [], error: "O ajudante de administrador não respondeu (código " + r.code + ")" };
    return JSON.parse(read(out));
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
}

// ---------------------------------------------------------------- antivírus: ClamAV (se instalado)
const CLAM_MSG = "No Linux o antivírus é o ClamAV (opcional): sudo apt install clamav";
async function defender(args) {
  if (!has("clamscan")) return { code: 99, out: "", err: CLAM_MSG };
  if (args[0] === "-SignatureUpdate") return run("pkexec", ["freshclam"], { timeout: 20 * 60000 });
  const full = args.includes("2");
  const dirs = full ? [HOME] : ["Downloads", "Transferências", "Desktop", "Área de Trabalho", ".local/share/applications", ".config/autostart"].map((d) => path.join(HOME, d)).filter(exists);
  const r = await run("clamscan", ["-r", "-i", "--no-summary", ...dirs], { timeout: 6 * 3600 * 1000 });
  return { ...r, code: r.code === 1 ? 2 : r.code }; // 1 = ameaça (como o 2 do Defender)
}
async function scanFile(p) {
  if (!has("clamscan")) return { clean: false, threat: false, code: 99, output: CLAM_MSG };
  const r = await run("clamscan", ["--no-summary", p], { timeout: 10 * 60000 });
  return { clean: r.code === 0, threat: r.code === 1, code: r.code, output: (r.out || r.err).trim().slice(-600) };
}

// ---------------------------------------------------------------- Vigia: o que comparar a cada 15 min
const sig = (raw) => ({
  auto: [...(raw.autostart || []).filter((a) => a.enabled).map((a) => `autostart|${a.name}|${a.command}`), ...(raw.cron || []).map((c) => `cron|${c}`), ...(raw.userUnits || []).map((u) => `unit|${u.name}|${u.exec}`)],
  services: (raw.systemUnits || []).map((s) => `${s.name}|${s.exec}`), admins: (raw.admins || []).map((x) => x.name), users: (raw.users || []).filter((u) => u.enabled).map((u) => u.name),
  hosts: raw.hosts || [], proxy: [String((raw.proxy || {}).mode)], remote: ((raw.remote || {}).installed || []).map((x) => x.name),
  sshkeys: raw.sshKeys || [], preload: raw.preload ? [raw.preload] : [],
});
const WHAT = { auto: "Algo novo vai abrir sozinho", services: "Serviço novo no sistema", admins: "Nova conta de administrador (sudo)", users: "Nova conta de usuário", hosts: "O arquivo hosts mudou",
  proxy: "O proxy da internet mudou", remote: "Programa de acesso remoto instalado", sshkeys: "Nova chave SSH pode entrar na sua conta", preload: "Biblioteca forçada em todos os programas (ld.so.preload)" };

module.exports = { collect, analyze, FIXES, apply, defender, scanFile, sig, WHAT };
