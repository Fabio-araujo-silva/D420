#!/usr/bin/env python3
"""resolve-unlocked: vira o flag "IsStudio" do DaVinci Resolve com um patch
binario de 6 bytes, reversivel e localizado por assinatura (nao por offset).

Uso basico:
    python patcher.py status  --dir "C:\\Program Files\\Blackmagic Design\\DaVinci Resolve"
    python patcher.py patch   --dir ...
    python patcher.py unpatch --dir ...
    python patcher.py detect  --dir ...

Zero dependencias externas. Python 3.11+ (usa tomllib).
"""

import argparse
import hashlib
import os
import re
import sys
import tomllib

HERE = os.path.dirname(os.path.abspath(__file__))
PROFILES_DIR = os.path.join(HERE, "profiles")
BACKUP_SUFFIX = ".resolve-unlocked.bak"


# ---------- assinaturas: hex com '??' como curinga ----------

def parse_sig(sig: str) -> bytes:
    """'4c8bc2??' -> (bytes, mask) com byte a byte; '??' casa qualquer valor."""
    hexstr = sig.replace(" ", "").lower()
    if len(hexstr) % 2 != 0:
        raise ValueError(f"assinatura com numero impar de digitos: {sig!r}")
    raw = bytearray()
    mask = bytearray()
    for i in range(0, len(hexstr), 2):
        pair = hexstr[i:i + 2]
        if pair == "??":
            raw.append(0)
            mask.append(0)
        else:
            raw.append(int(pair, 16))
            mask.append(0xFF)
    return bytes(raw), bytes(mask)


def find_all(data: bytes, sig: str) -> list[int]:
    """Todas as posicoes onde a assinatura (com curingas '??') casa.
    Regex com lookahead para permitir ocorrecoes sobrepostas."""
    raw, mask = parse_sig(sig)
    pat = b"".join(b"." if not mk else re.escape(bytes([b])) for b, mk in zip(raw, mask))
    return [m.start() for m in re.finditer(b"(?=" + pat + b")", data)]


def sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# ---------- perfis ----------

def load_profiles(only: str | None = None) -> list[dict]:
    profiles = []
    for name in sorted(os.listdir(PROFILES_DIR)):
        if not name.endswith(".toml"):
            continue
        if only and not name.startswith(only):
            continue
        with open(os.path.join(PROFILES_DIR, name), "rb") as fh:
            p = tomllib.load(fh)
        p["_file"] = name
        profiles.append(p)
    return profiles


def evaluate(install_dir: str, profile: dict) -> dict | None:
    """Para cada alvo do perfil, diz o estado: 'original', 'patched',
    'missing' (arquivo nao existe), 'unknown' (nenhuma assinatura casou),
    'ambiguous' (casou mais de uma vez ou casaram as duas)."""
    result = {"profile": profile["_file"], "version": profile.get("version"), "targets": []}
    any_match = False
    for t in profile.get("target", []):
        path = os.path.join(install_dir, t["file"])
        entry = {"name": t["name"], "file": t["file"], "path": path}
        if not os.path.exists(path):
            entry["state"] = "missing"
            result["targets"].append(entry)
            continue
        data = open(path, "rb").read()
        n_orig = len(find_all(data, t["sig"]))
        n_patch = len(find_all(data, t["patched"]))
        if n_orig == 1 and n_patch == 0:
            entry["state"] = "original"
            any_match = True
        elif n_patch == 1 and n_orig == 0:
            entry["state"] = "patched"
            any_match = True
        elif n_orig == 0 and n_patch == 0:
            entry["state"] = "unknown"
        else:
            entry["state"] = "ambiguous"
        entry["sha256"] = None
        if "sha256_original" in t:
            expected = t["sha256_original"]
            cur = sha256(path)
            entry["sha256"] = cur
            entry["sha_ok"] = (cur == expected)
        result["targets"].append(entry)
    result["matches"] = any_match
    return result


def pick_profile(install_dir: str, profiles: list[dict]) -> dict | None:
    """Primeiro perfil em que todo arquivo-alvo existe e nenhum alvo deu
    'ambiguous'; pelo menos um alvo precisa casar original ou patched."""
    best = None
    for p in profiles:
        r = evaluate(install_dir, p)
        states = {t["state"] for t in r["targets"]}
        if "ambiguous" in states:
            continue
        if r["matches"] and "unknown" not in states and "missing" not in states:
            return p
        if r["matches"] and best is None:
            best = p
    return best


# ---------- comandos ----------

def cmd_report(install_dir: str, profile: dict) -> int:
    r = evaluate(install_dir, profile)
    print(f"perfil: {r['profile']}  (Resolve {r['version']})")
    ok = True
    for t in r["targets"]:
        sha = ""
        if t.get("sha256") is not None:
            sha = "  [sha ok]" if t.get("sha_ok") else "  [SHA DIFERE!]"
        print(f"  {t['file']:24} {t['name']:44} -> {t['state']}{sha}")
        if t["state"] in ("unknown", "ambiguous", "missing"):
            ok = False
    return 0 if ok else 1


def cmd_detect(install_dir: str, profiles: list[dict]) -> int:
    for p in profiles:
        r = evaluate(install_dir, p)
        states = [t["state"] for t in r["targets"]]
        print(f"{r['profile']:16} {'/'.join(set(states)) if states else '-':30} "
              f"{sum(s in ('original','patched') for s in states)}/{len(states)} alvos reconhecidos")
    chosen = pick_profile(install_dir, profiles)
    if chosen:
        print(f"\n=> perfil escolhido automaticamente: {chosen['_file']}")
        return 0
    print("\n=> nenhum perfil bateu com esta instalacao. Versao nova? "
          "Veja 'Como adicionar uma versao' no README.")
    return 2


def _lock_ok(path: str) -> bool:
    try:
        with open(path, "r+b"):
            return True
    except OSError:
        return False


def _apply(install_dir: str, profile: dict, want: str) -> int:
    """want: 'patched' para aplicar, 'original' para reverter."""
    from_state, to_state = ("original", "patched") if want == "patched" else ("patched", "original")
    r = evaluate(install_dir, profile)
    todo = []
    for t in r["targets"]:
        if t["state"] == from_state:
            todo.append(t)
        elif t["state"] != to_state:
            print(f"ERRO: {t['file']} esta '{t['state']}' — nada foi tocado. "
                  f"Saindo por seguranca (sem patch parcial).")
            return 1
    if not todo:
        print(f"nada a fazer: ja esta '{to_state}'.")
        return 0
    # trava: nenhum arquivo pode estar em uso
    for t in todo:
        if not _lock_ok(t["path"]):
            print(f"ERRO: {t['file']} esta em uso (o Resolve esta aberto?).")
            return 1
    # backup unico por arquivo
    for t in todo:
        bak = t["path"] + BACKUP_SUFFIX
        if not os.path.exists(bak):
            with open(t["path"], "rb") as src, open(bak, "wb") as dst:
                dst.write(src.read())
            print(f"backup: {os.path.basename(bak)}")
    for t in todo:
        prof_t = next(x for x in profile["target"] if x["name"] == t["name"])
        data = bytearray(open(t["path"], "rb").read())
        if want == "patched":
            at = find_all(bytes(data), prof_t["sig"])[0]
            new, _ = parse_sig(prof_t["patched"])
            data[at:at + len(new)] = new
        else:
            at = find_all(bytes(data), prof_t["patched"])[0]
            new, _ = parse_sig(prof_t["sig"])
            data[at:at + len(new)] = new
        with open(t["path"], "wb") as fh:
            fh.write(data)
        verb = "patcheado" if want == "patched" else "revertido"
        print(f"{verb}: {t['file']} :: {t['name']} (offset {at:#x})")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="resolve-unlocked: patch de 6 bytes no DaVinci Resolve")
    ap.add_argument("cmd", choices=["detect", "status", "patch", "unpatch"])
    ap.add_argument("--dir", required=True, help="pasta de instalacao do Resolve")
    ap.add_argument("--profile", help="forca um perfil (ex.: 21.2)")
    args = ap.parse_args(argv)

    if not os.path.isdir(args.dir):
        print(f"ERRO: pasta nao existe: {args.dir}")
        return 1

    profiles = load_profiles(args.profile)
    if not profiles:
        print("ERRO: nenhum perfil em profiles/")
        return 1

    if args.cmd == "detect":
        return cmd_detect(args.dir, profiles)

    profile = next((p for p in profiles if args.profile and p["_file"].startswith(args.profile)),
                   None) or pick_profile(args.dir, profiles)
    if not profile:
        print("ERRO: nao reconheci a versao (nenhum perfil bateu). Use --profile ou rode 'detect'.")
        return 2

    if args.cmd == "status":
        return cmd_report(args.dir, profile)
    if args.cmd == "patch":
        return _apply(args.dir, profile, "patched")
    if args.cmd == "unpatch":
        return _apply(args.dir, profile, "original")
    return 1


if __name__ == "__main__":
    sys.exit(main())
