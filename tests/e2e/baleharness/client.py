"""Git client setup: isolated HOME, ssh agent/keys, remote URLs."""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

from baleharness.logutil import TestFailure
from baleharness.proc import run


class SshAgent:
    """Per-test `ssh-agent` so a bare `ssh` with no `-i` (git-bale's
    forge-auth subprocess) gets the key via `SSH_AUTH_SOCK` instead of ssh's
    default identity lookup, which system ssh_config or `IdentitiesOnly`
    can defeat."""

    def __init__(self) -> None:
        self.sock: str | None = None
        self.pid: int | None = None

    def start(self, identity_file: Path) -> None:
        out = subprocess.check_output(["ssh-agent", "-s"]).decode("utf-8")
        for raw in out.splitlines():
            line = raw.strip()
            if line.startswith("SSH_AUTH_SOCK="):
                self.sock = line[len("SSH_AUTH_SOCK=") :].split(";", 1)[0]
            elif line.startswith("SSH_AGENT_PID="):
                self.pid = int(line[len("SSH_AGENT_PID=") :].split(";", 1)[0])
        if self.sock is None or self.pid is None:
            raise TestFailure(f"could not parse `ssh-agent -s` output:\n{out}")
        env = os.environ.copy()
        env["SSH_AUTH_SOCK"] = self.sock
        completed = subprocess.run(
            ["ssh-add", str(identity_file)],
            env=env,
            capture_output=True,
            check=False,
        )
        if completed.returncode != 0:
            raise TestFailure(
                f"ssh-add failed (exit {completed.returncode}):\n"
                f"stdout:\n{completed.stdout.decode('utf-8', 'replace')}\n"
                f"stderr:\n{completed.stderr.decode('utf-8', 'replace')}"
            )

    def stop(self) -> None:
        if self.pid is None:
            return
        try:
            os.kill(self.pid, 15)  # SIGTERM
        except OSError:
            pass
        self.pid = None
        self.sock = None


@dataclass
class ClientEnv:
    home: Path
    ssh_key: Path
    ssh_pub: Path
    known_hosts: Path
    gitconfig: Path
    ssh_config: Path
    git_bale_bin: Path
    ssh_agent: SshAgent | None = None

    def make_env(self) -> dict:
        env = os.environ.copy()
        env["HOME"] = str(self.home)
        if os.name == "nt":
            env["USERPROFILE"] = str(self.home)
        env["GIT_CONFIG_GLOBAL"] = str(self.gitconfig)
        env["GIT_CONFIG_NOSYSTEM"] = "1"
        # The pre-push hook runs `git-bale push-pending` with no path; the
        # release binary's directory must be on PATH for the hook to find it.
        env["PATH"] = str(self.git_bale_bin.parent) + os.pathsep + env.get("PATH", "")
        env["GIT_AUTHOR_NAME"] = "Bale E2E"
        env["GIT_AUTHOR_EMAIL"] = "e2e@bale.invalid"
        env["GIT_COMMITTER_NAME"] = "Bale E2E"
        env["GIT_COMMITTER_EMAIL"] = "e2e@bale.invalid"
        # Tests assert prompt reclamation, so disable gc's reclaim grace
        # (default 2 weeks); the `local-gc-grace` phase overrides it.
        env["BALE_GC_GRACE_SECS"] = "0"
        # Isolated identity, no user/system ssh config. git shell-word-splits
        # this (sh on Git-for-Windows), so paths are forward-slash and quoted
        # (a backslash reads as an escape). `-F` is a real empty file, not the
        # null device: Git-for-Windows' bundled MSYS OpenSSH treats `nul` as a
        # relative filename and dies with "Can't open user config file nul".
        env["GIT_SSH_COMMAND"] = (
            f'ssh -F "{self.ssh_config.as_posix()}" -i "{self.ssh_key.as_posix()}" '
            f"-o IdentitiesOnly=yes "
            f'-o UserKnownHostsFile="{self.known_hosts.as_posix()}" '
            f"-o StrictHostKeyChecking=no -o BatchMode=yes"
        )
        # git-bale's forge-auth runs bare `ssh` (no -i); the agent supplies the key.
        if self.ssh_agent is not None and self.ssh_agent.sock is not None:
            env["SSH_AUTH_SOCK"] = self.ssh_agent.sock
            # A host SSH_AGENT_PID would point at a different agent than our socket.
            env.pop("SSH_AGENT_PID", None)
        return env


def _lock_private_key(path: Path) -> None:
    """ssh refuses a key other users can read. Win32 OpenSSH ignores mode
    bits and checks the ACL ("UNPROTECTED PRIVATE KEY FILE"), so on Windows
    strip inherited ACEs and grant only the current user."""
    if os.name == "nt":
        user = os.environ.get("USERNAME") or os.environ.get("USER")
        subprocess.run(
            ["icacls", str(path), "/inheritance:r"],
            capture_output=True,
            check=False,
        )
        if user:
            subprocess.run(
                ["icacls", str(path), "/grant:r", f"{user}:F"],
                capture_output=True,
                check=False,
            )
    else:
        os.chmod(path, 0o600)


def setup_client(*, work_root: Path, git_bale_bin: Path) -> ClientEnv:
    home = work_root / "home"
    ssh_dir = home / ".ssh"
    ssh_dir.mkdir(parents=True)
    # ssh refuses identities from a .ssh dir with mode > 0700 (Windows: see
    # _lock_private_key).
    if os.name != "nt":
        os.chmod(ssh_dir, 0o700)
    gitconfig = work_root / "gitconfig"
    gitconfig.write_text("")
    ssh_key = ssh_dir / "id_ed25519"
    ssh_pub = ssh_dir / "id_ed25519.pub"
    known_hosts = ssh_dir / "known_hosts"
    known_hosts.touch()
    # Empty config so `-F` neutralizes any user/system ssh config portably.
    ssh_config = ssh_dir / "config"
    ssh_config.write_text("")
    run(
        [
            "ssh-keygen",
            "-t",
            "ed25519",
            "-f",
            str(ssh_key),
            "-N",
            "",
            "-C",
            "baleforgit-e2e",
            "-q",
        ],
    )
    _lock_private_key(ssh_key)
    if os.name != "nt":
        os.chmod(ssh_pub, 0o644)
    # Windows has no per-process agent: forge-auth's bare `ssh` falls back to
    # %USERPROFILE%\.ssh\id_ed25519, which is this key (USERPROFILE = our HOME).
    agent: SshAgent | None = None
    if os.name != "nt":
        agent = SshAgent()
        agent.start(ssh_key)
    return ClientEnv(
        home=home,
        ssh_key=ssh_key,
        ssh_pub=ssh_pub,
        known_hosts=known_hosts,
        gitconfig=gitconfig,
        ssh_config=ssh_config,
        git_bale_bin=git_bale_bin,
        ssh_agent=agent,
    )


def remote_url_ssh(*, ssh_port: int, owner: str, repo: str) -> str:
    """ssh:// rather than scp-style: scp-style can't carry a port, so both
    git and git-bale's own ssh subprocess would need a per-server ssh-config
    alias. The path is absolute server-side; the entrypoint symlinks
    `/<owner>` -> `/home/git/<owner>` so it resolves, and git-bale splits it
    on the first `/` into owner/repo for forge auth."""
    return f"ssh://git@127.0.0.1:{ssh_port}/{owner}/{repo}.git"
