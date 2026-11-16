#!/usr/bin/env python3
"""
Build a tiny fake web server folder, then (optionally) simulate what an attacker
typically changes after compromising it. Used for the hashguard tutorial.

    python3 demo/simulate_attack.py setup   # creates demo/webroot
    hashguard init demo/webroot
    python3 demo/simulate_attack.py attack  # tamper with files
    hashguard check demo/webroot

Everything is harmless: the "webshell" is a PHP *comment* containing typical
signatures, so it never executes anything.
"""
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent / "webroot"

FILES = {
    "index.php": "<?php include 'header.php'; ?>\n<h1>Welcome to Auto Parts Shop</h1>\n",
    "header.php": "<?php session_start(); ?>\n<nav>Home | Products | Contact</nav>\n",
    "products.php": "<?php $id = (int)$_GET['id']; /* prepared statements used */ ?>\n",
    ".htaccess": "Options -Indexes\nServerSignature Off\n",
    "assets/style.css": "body { font-family: sans-serif; }\n",
    "assets/logo.svg": "<svg xmlns='http://www.w3.org/2000/svg'><circle r='10'/></svg>\n",
    "config/app.ini": "[db]\nhost=127.0.0.1\nname=shop\n",
    "logs/access.log": "127.0.0.1 - - GET / 200\n",
}


def setup():
    if ROOT.exists():
        shutil.rmtree(ROOT)
    for rel, content in FILES.items():
        p = ROOT / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    print(f"[+] demo web root created: {ROOT}  ({len(FILES)} files)")


def attack():
    # 1. drop a (fake) webshell in the uploads folder
    (ROOT / "uploads").mkdir(exist_ok=True)
    (ROOT / "uploads" / "img_2291.php").write_text(
        "<?php /* DEMO ONLY - not executable. Typical webshell signature: "
        "eval(base64_decode($_POST['x'])) */ ?>\n")
    # 2. backdoor an existing page
    with open(ROOT / "header.php", "a") as f:
        f.write("<?php /* DEMO: injected line -> shell_exec($_GET['c']) */ ?>\n")
    # 3. weaken server config
    (ROOT / ".htaccess").write_text("Options +Indexes\nAddType application/x-httpd-php .jpg\n")
    # 4. persistence script + covering tracks
    (ROOT / "assets" / "update.sh").write_text("#!/bin/sh\necho demo\n")
    (ROOT / "logs" / "access.log").unlink()
    # 5. normal, harmless change
    (ROOT / "assets" / "style.css").write_text("body { font-family: system-ui; }\n")
    print("[!] simulated attack applied: webshell, backdoored page, .htaccess, new script, deleted log, css edit")


if __name__ == "__main__":
    {"setup": setup, "attack": attack}.get(sys.argv[1] if len(sys.argv) > 1 else "", lambda: print(__doc__))()
