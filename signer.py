#!/usr/bin/env python3
import shutil, sys, os, subprocess, tempfile, secrets, string, pathlib

RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
RESET = "\033[0m"
BOLD = "\033[1m"

ascii_art = r"""
  ██████  ██▓  ▄████  ███▄    █ ▓█████  ██▀███
▒██    ▒ ▓██▒ ██▒ ▀█▒ ██ ▀█   █ ▓█   ▀ ▓██ ▒ ██▒
░ ▓██▄   ▒██▒▒██░▄▄▄░▓██  ▀█ ██▒▒███   ▓██ ░▄█ ▒
  ▒   ██▒░██░░▓█  ██▓▓██▒  ▐▌██▒▒▓█  ▄ ▒██▀▀█▄
▒██████▒▒░██░░▒▓███▀▒▒██░   ▓██░░▒████▒░██▓ ▒██▒
▒ ▒▓▒ ▒ ░░▓   ░▒   ▒ ░ ▒░   ▒ ▒ ░░ ▒░ ░░ ▒▓ ░▒▓░
░ ░▒  ░ ░ ▒ ░  ░   ░ ░ ░░   ░ ▒░ ░ ░  ░  ░▒ ░ ▒░
░  ░  ░   ▒ ░░ ░   ░    ░   ░ ░    ░     ░░   ░
      ░   ░        ░          ░    ░  ░   ░
                                https://github.com/X-croot
"""

print(f"{GREEN}{ascii_art}{RESET}")



def check_tool(name): return shutil.which(name) is not None

def install_instructions(tool):
    plat = sys.platform
    if plat.startswith("linux"):
        mgrs = (
            ("apt", f"sudo apt update && sudo apt install -y {tool}"),
            ("dnf", f"sudo dnf install -y {tool}"),
            ("pacman", f"sudo pacman -S {tool}")
        )
    elif plat == "darwin":
        mgrs = (("brew", f"brew install {tool}"),)
    elif plat.startswith("win"):
        mgrs = (("choco", f"choco install {tool} -y"),)
    else:
        mgrs = ()
    msg = [f"{RED}[-]{RESET} Tool {BOLD}{tool}{RESET} not found in PATH."]
    if mgrs:
        msg.append(f"{YELLOW}You can install it using:{RESET}")
        for n, c in mgrs: msg.append(f"  {BLUE}{n}:{RESET} {c}")
    else:
        msg.append(f"{RED}Please install it manually.{RESET}")
    return "\n".join(msg)

def random_str(n=10):
    return ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(n))

def run(cmd, **kw):
    return subprocess.run(cmd, **kw)

def main():
    need = ["openssl", "osslsigncode"]
    missing = [t for t in need if not check_tool(t)]
    if missing:
        print(f"{RED}[-] Missing required tools:{RESET}")
        for t in missing: print(install_instructions(t), "\n")
        print(f"{RED}[-] Install missing tools and re-run.{RESET}")
        sys.exit(1)

    cwd = pathlib.Path.cwd()
    exes = sorted([p for p in cwd.iterdir() if p.is_file() and p.suffix.lower() == ".exe"])
    if not exes:
        print(f"{RED}[-] No .exe found in {cwd}{RESET}")
        sys.exit(1)

    print(f"{YELLOW}[+] Found .exe files:{RESET}")
    for i, p in enumerate(exes, 1):
        print(f"  {BLUE}{i}){RESET} {p.name}")

    sel = None
    while True:
        try:
            s = input(f"{YELLOW}Select file to sign:{RESET} ").strip()
            idx = int(s)
            if 1 <= idx <= len(exes): sel = exes[idx-1]; break
        except Exception: pass
        print(f"{RED}Invalid selection, try again.{RESET}")

    out_path = cwd / f"{sel.stem}_signed.exe"

    with tempfile.TemporaryDirectory() as td:
        td_path = pathlib.Path(td)
        key_pem, cert_pem, pfx_file = td_path/"key.pem", td_path/"cert.pem", td_path/"cert.pfx"
        password = random_str(16)
        subj = f"/CN={random_str(12)}/O={random_str(8)}/C=US"

        print(f"{GREEN}[+] Generating temporary certificate...{RESET}")
        try:
            run(["openssl","req","-x509","-newkey","rsa:2048","-keyout",str(key_pem),
                 "-out",str(cert_pem),"-days","365","-nodes","-subj",subj],
                 check=True,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
        except subprocess.CalledProcessError as e:
            print(f"{RED}OpenSSL failed:{RESET}", e.stderr.decode(errors='ignore')); sys.exit(1)

        run(["openssl","pkcs12","-export","-inkey",str(key_pem),"-in",str(cert_pem),
             "-out",str(pfx_file),"-password",f"pass:{password}"],
             check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)

        print(f"{GREEN}[+] Certificate ready. Password:{RESET} {BOLD}{password}{RESET}")
        signed_tmp = td_path/"signed_tmp.exe"
        cmd = ["osslsigncode","sign","-pkcs12",str(pfx_file),"-pass",password,
               "-in",str(sel),"-out",str(signed_tmp),"-h","sha256"]
        print(f"{GREEN}[+] Signing {sel.name} ...{RESET}")
        try:
            proc = run(cmd,check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            if proc.stdout: print(proc.stdout.decode(errors='ignore'))
            if proc.stderr: print(proc.stderr.decode(errors='ignore'))
        except subprocess.CalledProcessError as e:
            print(f"{RED}osslsigncode failed.{RESET}")
            if e.stderr: print(e.stderr.decode(errors='ignore'))
            sys.exit(1)

        shutil.copy(str(signed_tmp), str(out_path))
        print(f"{GREEN}[+] Signed file saved as:{RESET} {BLUE}{out_path.name}{RESET}")
        print(f"{YELLOW}Temporary cert & key cleared from memory.{RESET}")

    print(f"{GREEN}[✓] Done!{RESET} {YELLOW}Note: self-signed for testing only.{RESET}")

if __name__ == "__main__":
    main()
