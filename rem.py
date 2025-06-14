#!/usr/bin/env python3
import subprocess, sys, shutil
from pathlib import Path

# 🔧 Paths to remove from the repo history
REMOVE_PATHS = [
    "x64/Release/Found_Eth.txt",
    "x64/Release/KeyHunt-Cuda.exe",
    "x64/Release/addresses_to_hash160.py",
    "x64/Release/eth_addresses_to_bin.py",
    "x64/Release/pubkeys_to_xpoint.py",
    "x64/Release/puzzle_1_37_addresses_eth.bin",
    "x64/Release/puzzle_1_37_addresses_eth_sorted.bin",
    "x64/Release/puzzle_1_37_hash160_out.bin",
    "x64/Release/puzzle_1_37_hash160_out_sorted.bin",
    "x64/Release/xpoints_1_37_out.bin",
    "x64/Release/xpoints_1_37_out_sorted.bin",
]

def run(cmd, **kw):
    print(f"> {' '.join(cmd)}")
    return subprocess.run(cmd, check=True, **kw)

def ensure_filter_repo():
    if shutil.which("git-filter-repo") or shutil.which("git-filter-repo.exe"):
        print("✅ git-filter-repo is already installed")
        return
    print("✨ Installing git-filter-repo via pip")
    run([sys.executable, "-m", "pip", "install", "--user", "git-filter-repo"])
    # Optionally, verify after install
    if not (shutil.which("git-filter-repo") or shutil.which("git-filter-repo.exe")):
        print("⚠️ git-filter-repo not found in PATH. Please ensure ~/.local/bin is in your PATH.")
        sys.exit(1)

def main():
    ensure_filter_repo()
    repo = input("GitHub HTTPS repo URL: ").strip()
    mirror = Path("repo-mirror.git")

    # 1. Mirror clone
    run(["git", "clone", "--mirror", repo, str(mirror)])

    # 2. Write remove-list.txt
    remove_list = mirror / "remove-list.txt"
    remove_list.write_text("\n".join(REMOVE_PATHS))
    print(f"📝 Write remove-list to {remove_list}")

    # 3. Run filter-repo to purge files
    run([
        "git", "filter-repo",
        "--force",
        "--invert-paths",
        "--paths-from-file", str(remove_list),
        "--refs", "--all"
    ], cwd=mirror)

    # 4. Push cleaned history
    run(["git", "push", "--force", "--mirror", repo], cwd=mirror)

    print("🎉 All specified files removed from history and changes pushed!")

if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as e:
        print(f"\n❌ Error running: {e.cmd}\nExit code: {e.returncode}", file=sys.stderr)
        sys.exit(1)
