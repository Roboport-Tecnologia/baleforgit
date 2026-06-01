"""Repo bootstrap (the user-side push/clone repos)."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from baleharness.client import ClientEnv, remote_url_ssh
from baleharness.gitutil import git
from baleharness.proc import run
from baleharness.server import ServerHandle


def init_repo_for_push(
    *,
    work_root: Path,
    client: ClientEnv,
    server: ServerHandle,
    owner: str,
    repo: str,
    name: str = "alice",
) -> tuple[Path, dict]:
    """Init a working repo, install the bale filter, set the SSH remote
    pointing at `server`, and seed `.gitattributes`. Returns (repo_path,
    env). The remote URL carries the server's SSH port, so multiple
    servers can coexist without any ssh-config gymnastics."""
    env = client.make_env()
    work = work_root / name
    work.mkdir()
    git(["init", "-b", "main", "."], cwd=work, env=env)
    # `install --local` writes filter.bale.process + required=true AND the
    # pre-push hook that runs `git-bale push-pending`.
    run([str(client.git_bale_bin), "install", "--local"], cwd=work, env=env)
    cache_dir = work_root / f"cache-{name}"
    cache_dir.mkdir(exist_ok=True)
    git(["config", "--local", "bale.cacheDir", str(cache_dir)], cwd=work, env=env)
    git(
        [
            "remote",
            "add",
            "origin",
            remote_url_ssh(ssh_port=server.ssh_port, owner=owner, repo=repo),
        ],
        cwd=work,
        env=env,
    )
    (work / ".gitattributes").write_text("*.bin filter=bale -text\n")
    git(["add", ".gitattributes"], cwd=work, env=env)
    git(["commit", "-m", "enable bale filter"], cwd=work, env=env)
    return work, env


def init_repo_local(
    *,
    work_root: Path,
    client: ClientEnv,
    name: str,
    shared_store: Optional[Path] = None,
    track_glob: str = "*.bin",
) -> tuple[Path, dict]:
    """Init a working repo in fully-local mode. No server remote is configured.
    With `shared_store`, all such repos point at one store dir."""
    work = work_root / name
    work.mkdir(parents=True)
    env = client.make_env()
    # Remove server-targeting vars so the smudge filter never tries a network
    # path even if the harness env happened to carry stale server coordinates.
    env.pop("BALE_SERVER_URL", None)
    env.pop("BALE_TOKEN", None)
    git(["init", "-b", "main", "."], cwd=work, env=env)
    cmd = [str(client.git_bale_bin), "init-local"]
    if shared_store is not None:
        cmd += ["--shared", "--store", str(shared_store)]
    run(cmd, cwd=work, env=env)
    run([str(client.git_bale_bin), "track", track_glob], cwd=work, env=env)
    git(["add", ".gitattributes"], cwd=work, env=env)
    git(["commit", "-m", "track"], cwd=work, env=env)
    return work, env


def init_repo_for_clone(
    *,
    work_root: Path,
    client: ClientEnv,
    server: ServerHandle,
    owner: str,
    repo: str,
    name: str,
) -> tuple[Path, dict, Path]:
    """Clone over SSH with --no-checkout, install the filter, configure a
    fresh cache dir, then checkout. Returns (repo_path, env, cache_dir).
    The fresh cache means smudge will run through the cold network path,
    which is what most clone-side checks need."""
    env = client.make_env()
    target = work_root / name
    cache_dir = work_root / f"cache-{name}"
    cache_dir.mkdir(exist_ok=True)
    url = remote_url_ssh(ssh_port=server.ssh_port, owner=owner, repo=repo)
    git(["clone", "--no-checkout", url, str(target)], cwd=work_root, env=env)
    run([str(client.git_bale_bin), "install", "--local"], cwd=target, env=env)
    git(["config", "--local", "bale.cacheDir", str(cache_dir)], cwd=target, env=env)
    return target, env, cache_dir
