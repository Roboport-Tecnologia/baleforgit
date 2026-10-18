"""Repo bootstrap (the user-side push/clone repos)."""

from __future__ import annotations

from pathlib import Path

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
    """Repo with the filter installed, an SSH `origin` on `server`, and
    `*.bin` tracked. The URL carries the server's SSH port, so several servers
    coexist without ssh-config."""
    env = client.make_env()
    work = work_root / name
    work.mkdir()
    git(["init", "-b", "main", "."], cwd=work, env=env)
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
    shared_store: Path | None = None,
    track_glob: str = "*.bin",
) -> tuple[Path, dict]:
    """Fully-local repo, no remote; `shared_store` makes repos share one store."""
    work = work_root / name
    work.mkdir(parents=True)
    env = client.make_env()
    # Stale server coordinates in the harness env must not reach the filter.
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
    """`--no-checkout` clone with the filter installed and a fresh cache dir;
    the caller checks out, so smudge takes the cold network path.
    Returns (repo_path, env, cache_dir)."""
    env = client.make_env()
    target = work_root / name
    cache_dir = work_root / f"cache-{name}"
    cache_dir.mkdir(exist_ok=True)
    url = remote_url_ssh(ssh_port=server.ssh_port, owner=owner, repo=repo)
    git(["clone", "--no-checkout", url, str(target)], cwd=work_root, env=env)
    run([str(client.git_bale_bin), "install", "--local"], cwd=target, env=env)
    git(["config", "--local", "bale.cacheDir", str(cache_dir)], cwd=target, env=env)
    return target, env, cache_dir
