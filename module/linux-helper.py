# Piphin Escudo · ajudante de administrador do Linux (roda pelo pkexec, uma senha para tudo).
# Só conhece as ações abaixo; qualquer outra coisa no pedido é recusada.
#   collect  lê o que só o administrador vê: regras do sudo sem senha e tarefas agendadas do sistema
#   fix      ufw_on, ufw_install, ssh_root_off, autologin_off, unattended_on (com o valor anterior para desfazer)
# Uso: pkexec python3 -I linux-helper.py <pedido.json> <resposta.json>
import glob
import json
import os
import re
import subprocess
import sys

SSH_DROPIN = "/etc/ssh/sshd_config.d/99-piphin-escudo.conf"
GDM = "/etc/gdm3/custom.conf"
AUTO_UPG = "/etc/apt/apt.conf.d/20auto-upgrades"


def read(p):
    try:
        with open(p, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return None


def write(p, text):
    with open(p, "w", encoding="utf-8") as fh:
        fh.write(text)


def sh(argv, timeout=600):
    p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, env={**os.environ, "DEBIAN_FRONTEND": "noninteractive", "LC_ALL": "C"})
    if p.returncode != 0:
        raise RuntimeError((p.stderr or p.stdout).strip()[-300:] or f"{argv[0]} falhou")
    return p.stdout


def collect():
    nopasswd = []
    for f in ["/etc/sudoers", *sorted(glob.glob("/etc/sudoers.d/*"))]:
        for line in (read(f) or "").splitlines():
            if "NOPASSWD" in line and not line.strip().startswith("#"):
                nopasswd.append(f"{os.path.basename(f)}: {line.strip()[:200]}")
    cron = []
    for f in ["/etc/crontab", *sorted(glob.glob("/etc/cron.d/*")), "/var/spool/cron/crontabs/root"]:
        for line in (read(f) or "").splitlines():
            if line.strip() and not line.strip().startswith("#") and not re.match(r"^\w+=", line.strip()):
                cron.append(line.strip()[:300])
    return {"ok": True, "nopasswd": nopasswd, "rootCron": cron}


def reload_ssh():
    for unit in ("ssh", "sshd"):
        if subprocess.run(["systemctl", "reload", unit], capture_output=True).returncode == 0:
            return


def fix(a):
    f, undo, b = a.get("fix"), bool(a.get("undo")), a.get("backup") or {}
    if f == "ufw_on":
        if undo:
            if not b.get("was"):
                sh(["ufw", "disable"])
            return {"ok": True, "message": "Desfeito"}
        was = bool(re.search(r"^ENABLED=yes", read("/etc/ufw/ufw.conf") or "", re.M))
        sh(["ufw", "--force", "enable"])
        return {"ok": True, "backup": {"was": was}, "message": "Firewall ligado"}
    if f == "ufw_install":
        sh(["apt-get", "install", "-y", "ufw"], timeout=1200)
        sh(["ufw", "--force", "enable"])
        return {"ok": True, "message": "Firewall instalado e ligado"}
    if f == "ssh_root_off":
        if undo:
            if os.path.exists(SSH_DROPIN):
                os.unlink(SSH_DROPIN)
            reload_ssh()
            return {"ok": True, "message": "Desfeito"}
        os.makedirs(os.path.dirname(SSH_DROPIN), exist_ok=True)
        write(SSH_DROPIN, "# Piphin Escudo: sem login direto como root\nPermitRootLogin no\n")
        reload_ssh()
        return {"ok": True, "backup": {}, "message": "O SSH não aceita mais login como root"}
    if f == "autologin_off":
        if undo:
            if b.get("text") is not None:
                write(GDM, b["text"])
            return {"ok": True, "message": "Desfeito (vale no próximo login)"}
        text = read(GDM)
        if text is None:
            raise RuntimeError("Este sistema não usa o GDM (tela de login do GNOME)")
        write(GDM, re.sub(r"^(\s*)AutomaticLoginEnable\s*=.*$", r"\1AutomaticLoginEnable=false", text, flags=re.M))
        return {"ok": True, "backup": {"text": text}, "message": "Login automático desligado"}
    if f == "unattended_on":
        if undo:
            if b.get("text") is None:
                if os.path.exists(AUTO_UPG):
                    os.unlink(AUTO_UPG)
            else:
                write(AUTO_UPG, b["text"])
            return {"ok": True, "message": "Desfeito"}
        old = read(AUTO_UPG)
        write(AUTO_UPG, 'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n')
        return {"ok": True, "backup": {"text": old}, "message": "Atualizações de segurança automáticas ligadas"}
    raise ValueError("correção desconhecida")


def main():
    job, out = sys.argv[1], sys.argv[2]
    with open(job, encoding="utf-8") as fh:
        actions = json.load(fh).get("actions", [])
    res = {"ok": True, "actions": []}
    for a in actions:
        try:
            if a.get("type") == "collect":
                r = collect()
            elif a.get("type") == "fix":
                r = fix(a)
            else:
                raise ValueError("ação desconhecida")
        except Exception as e:  # noqa: BLE001
            r = {"ok": False, "error": str(e)}
        res["actions"].append(r)
    write(out, json.dumps(res))
    try:
        os.chown(out, os.stat(job).st_uid, os.stat(job).st_gid)
    except OSError:
        pass


if __name__ == "__main__":
    main()
