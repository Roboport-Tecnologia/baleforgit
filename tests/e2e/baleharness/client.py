"""Git client setup: isolated HOME, ssh agent/keys, remote URLs."""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from baleharness.logutil import TestFailure
from baleharness.proc import run


class SshAgent:
    """Manages a per-test `ssh-agent` so subprocesses that invoke `ssh`
    without an `-i` flag (notably git-bale's forge-auth subprocess) can
    still authenticate. Without the agent, git-bale would rely on ssh's
    default identity-file lookup under `$HOME/.ssh/`, which is fragile
    across OS configurations (system-wide ssh_config can preempt it,
    `IdentitiesOnly` can disable it, etc.). The agent sidesteps all of
    that — any process that inherits `SSH_AUTH_SOCK` gets the key."""

    def __init__(self) -> None:
        self.sock: Optional[str] = None
        self.pid: Optional[int] = None

    def start(self, identity_file: Path) -> None:
        # `ssh-agent -s` prints sh-style assignments we parse.
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
    git_bale_bin: Path
    ssh_agent: Optional[SshAgent] = None

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
        # GIT_SSH_COMMAND wraps ssh so git uses our isolated identity and
        # ignores any user/system ssh config (`-F /dev/null`). The remote URL
        # is `ssh://git@127.0.0.1:PORT/...` — port lives in the URL, so we
        # don't need a per-server `Port` directive anywhere.
        env["GIT_SSH_COMMAND"] = (
            f"ssh -F /dev/null -i {self.ssh_key} -o IdentitiesOnly=yes "
            f"-o UserKnownHostsFile={self.known_hosts} "
            f"-o StrictHostKeyChecking=no -o BatchMode=yes"
        )
        # git-bale's forge-auth subprocess invokes bare `ssh` (no -i).
        # SSH_AUTH_SOCK hands it the same key via the agent without any
        # config dance.
        if self.ssh_agent is not None and self.ssh_agent.sock is not None:
            env["SSH_AUTH_SOCK"] = self.ssh_agent.sock
            # Defensive: a stale SSH_AGENT_PID inherited from the host
            # would confuse our agent's lifecycle.
            env.pop("SSH_AGENT_PID", None)
        return env


def setup_client(*, work_root: Path, git_bale_bin: Path) -> ClientEnv:
    home = work_root / "home"
    ssh_dir = home / ".ssh"
    ssh_dir.mkdir(parents=True)
    # ssh refuses to offer identities from a .ssh dir with mode > 0700.
    os.chmod(ssh_dir, 0o700)
    gitconfig = work_root / "gitconfig"
    gitconfig.write_text("")
    ssh_key = ssh_dir / "id_ed25519"
    ssh_pub = ssh_dir / "id_ed25519.pub"
    known_hosts = ssh_dir / "known_hosts"
    known_hosts.touch()
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
    # ssh strict-modes refuses keys with mode > 0600.
    os.chmod(ssh_key, 0o600)
    os.chmod(ssh_pub, 0o644)
    # git's ssh is fully driven by GIT_SSH_COMMAND (`-F /dev/null` etc.).
    # git-bale's ssh gets its identity from SSH_AUTH_SOCK (ssh-agent),
    # so no ~/.ssh/config is needed at all — we leave the file unset.
    agent = SshAgent()
    agent.start(ssh_key)
    return ClientEnv(
        home=home,
        ssh_key=ssh_key,
        ssh_pub=ssh_pub,
        known_hosts=known_hosts,
        gitconfig=gitconfig,
        git_bale_bin=git_bale_bin,
        ssh_agent=agent,
    )


def remote_url_ssh(*, ssh_port: int, owner: str, repo: str) -> str:
    """ssh:// URL `ssh://git@127.0.0.1:PORT/<owner>/<repo>.git`. The form
    matters: scp-style URLs can't carry a port, which would force us to
    keep an ssh-config alias per running server in sync with the test's
    isolated `$HOME`. The ssh:// form keeps the port in the URL so both
    `git`'s SSH transport and `git-bale`'s direct ssh subprocess derive
    the right port from argv (`-p PORT`) without any config dance.

    The path is absolute on the server side — git-receive-pack will open
    `/<owner>/<repo>.git`. The container's entrypoint creates a symlink
    `/<owner>` -> `/home/git/<owner>` so that absolute path resolves to
    the actual bare repo. The resolver splits the path on the FIRST `/`
    to extract owner/repo, so this URL also yields owner=<owner>,
    repo=<repo> for the Bale forge-auth handshake."""
    return f"ssh://git@127.0.0.1:{ssh_port}/{owner}/{repo}.git"
