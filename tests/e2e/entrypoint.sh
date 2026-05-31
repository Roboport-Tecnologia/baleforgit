#!/bin/sh
# Container entrypoint: generate ssh host keys + authorized_keys + bare repos
# + a fake git-bale-authenticate command, then start sshd and baleforgit-server
# side by side.

set -eu

log() { printf '[entrypoint] %s\n' "$*" >&2; }

# ---------------------------------------------------------------------------
# Bind-mounted /data is owned by the host's UID (or by host's mapped UID
# under rootless podman). Hand it to the `bale` user so the server can
# write to it. We also chmod 755 on the dir itself so files written under
# it (default 644) are readable by the host user when the test walks the
# data dir from outside the container.
# ---------------------------------------------------------------------------
if [ -d /data ]; then
    chown bale:bale /data
    chmod 755 /data
fi

# ---------------------------------------------------------------------------
# Required env (set by the harness via `podman run -e ...`)
# ---------------------------------------------------------------------------
: "${BALE_LISTEN:=0.0.0.0:8080}"
: "${BALE_DATA_ROOT:=/data}"
: "${BALE_JWT_SECRET_HEX:?BALE_JWT_SECRET_HEX must be set}"
: "${BALE_TRANSFER_SECRET_HEX:?BALE_TRANSFER_SECRET_HEX must be set}"
: "${BALE_PUBLIC_URL:?BALE_PUBLIC_URL must be set}"
: "${BALE_PUBLIC_HOST_URL:=${BALE_PUBLIC_URL}}"
: "${BALE_GRANTS:=}"
: "${E2E_HUB_TOKEN:?E2E_HUB_TOKEN must be set}"
: "${SSH_AUTHORIZED_KEY:?SSH_AUTHORIZED_KEY must be set}"
: "${TEST_REPOS:?TEST_REPOS must be set (space-separated owner/repo list)}"

export BALE_LISTEN BALE_DATA_ROOT BALE_JWT_SECRET_HEX BALE_TRANSFER_SECRET_HEX
export BALE_PUBLIC_URL BALE_GRANTS
# Optional pass-through.
[ -n "${BALE_DEFAULT_QUOTA_BYTES:-}" ] && export BALE_DEFAULT_QUOTA_BYTES
[ -n "${BALE_ADMIN_TOKEN_HEX:-}" ] && export BALE_ADMIN_TOKEN_HEX
[ -n "${RUST_LOG:-}" ] && export RUST_LOG
# Postgres metadata store. Setting BALE_POSTGRES_URL flips the server from the
# local SQLite meta.db to Postgres. The harness (run.py --meta postgres) sets it.
[ -n "${BALE_POSTGRES_URL:-}" ] && export BALE_POSTGRES_URL
# Coverage mode: run.py --coverage sets this to a /coverage/... path so
# the instrumented baleforgit-server writes .profraw files to the
# bind-mounted host dir. Unset in prod mode — no-op.
[ -n "${LLVM_PROFILE_FILE:-}" ] && export LLVM_PROFILE_FILE
# S3 backend pass-through. Setting BALE_S3_BUCKET (non-empty) flips the server
# from the local-filesystem store to S3. The harness (run_s3.py) sets these.
for v in BALE_S3_BUCKET BALE_S3_ENDPOINT_URL BALE_S3_FORCE_PATH_STYLE \
         BALE_S3_ACCESS_KEY_ID BALE_S3_SECRET_ACCESS_KEY \
         BALE_S3_REGION BALE_S3_DISABLE_SSE BALE_S3_PREFIX \
         BALE_S3_SESSION_TOKEN; do
    eval "[ -n \"\${$v:-}\" ] && export $v" || true
done

# ---------------------------------------------------------------------------
# SSH host keys: regenerate on every container start so a fresh server has
# fresh keys. The harness disables StrictHostKeyChecking so this is fine.
# ---------------------------------------------------------------------------
log "generating ssh host keys"
ssh-keygen -A >/dev/null

# ---------------------------------------------------------------------------
# Authorized key for the `git` user (one line). The /home/git tree is
# bind-mounted from the host so bare repos persist across container
# restarts — meaning the .ssh dir the Dockerfile baked in is masked, and
# we have to (re)create it here on every start.
# ---------------------------------------------------------------------------
mkdir -p /home/git/.ssh
printf '%s\n' "$SSH_AUTHORIZED_KEY" > /home/git/.ssh/authorized_keys
chown -R git:git /home/git
chmod 700 /home/git/.ssh
chmod 600 /home/git/.ssh/authorized_keys

# ---------------------------------------------------------------------------
# Bare repos under /home/git/<owner>/<repo>.git, plus a root-level symlink
# /<owner> -> /home/git/<owner> so ssh:// URLs like
# `ssh://git@host:PORT/<owner>/<repo>.git` (which carry the port the client
# needs) resolve to the bare repo on disk. The harness picks the URL shape
# precisely because ssh:// can carry a port — scp-style can't — and that
# sidesteps needing per-host ssh config entries on the client.
#
# The resolver splits the URL path on the FIRST `/` to extract owner/repo,
# so the on-disk layout has to keep owner one segment deep (no `repos/`
# nesting in between). Names come from $TEST_REPOS = "owner1/repo1
# owner2/repo2 ...".
# ---------------------------------------------------------------------------
for repo in $TEST_REPOS; do
    owner_dir=$(dirname "$repo")            # "e2e/repo" -> "e2e"
    repo_dir="/home/git/${repo}.git"        # /home/git/e2e/repo.git
    mkdir -p "$repo_dir"
    if [ ! -d "$repo_dir/objects" ]; then
        log "init bare repo $repo_dir"
        git init --bare --initial-branch=main "$repo_dir" >/dev/null
    fi
    chown -R git:git "/home/git/${owner_dir}"
    # Root-level symlink so an absolute SSH path like /e2e/repo.git
    # (which is what git emits for ssh:// URLs) resolves on the server.
    if [ ! -e "/${owner_dir}" ]; then
        ln -s "/home/git/${owner_dir}" "/${owner_dir}"
    fi
done

# ---------------------------------------------------------------------------
# Fake git-bale-authenticate command. The git-bale client SSHes in and runs
# `git-bale-authenticate <owner>/<repo> <upload|download>`. The script
# returns the JSON shape the resolver expects: an `href` pointing at
# baleforgit-server (host-side URL) and an `Authorization: Bearer <hub_token>`.
# Values are baked in at startup, so the SSH non-interactive shell doesn't
# need to source any rc files to see them.
# ---------------------------------------------------------------------------
log "writing /usr/local/bin/git-bale-authenticate"
cat > /usr/local/bin/git-bale-authenticate <<EOF
#!/bin/sh
# Args: \$1 = owner/repo, \$2 = upload|download. We ignore them in the test
# because BALE_GRANTS already covers every repo we'll touch — the response
# is fixed.
printf '%s\n' '{"href":"${BALE_PUBLIC_HOST_URL}","Authorization":"Bearer ${E2E_HUB_TOKEN}"}'
EOF
chmod 755 /usr/local/bin/git-bale-authenticate

# ---------------------------------------------------------------------------
# Start sshd. Foreground (-D) backgrounded with `&` so the script can keep
# going; `-e` sends log to stderr so `podman logs` picks it up.
#
# StrictModes=no: /home/git is bind-mounted from the host, and on a Windows
# host the podman VM's mount can't represent Unix ownership/modes — the
# `chmod 600` above is a no-op there, so authorized_keys looks world-writable
# and StrictModes would refuse it ("bad ownership or modes"), denying every
# publickey auth. Harmless on Linux/macOS where the modes are already correct.
# ---------------------------------------------------------------------------
log "starting sshd on :2222"
/usr/sbin/sshd -D -e -o StrictModes=no &
SSHD_PID=$!

# Trap so `podman stop` (SIGTERM) kills sshd too, not just the server.
cleanup() {
    log "shutting down (sshd pid=$SSHD_PID)"
    kill "$SSHD_PID" 2>/dev/null || true
}
trap cleanup INT TERM EXIT

# ---------------------------------------------------------------------------
# Run baleforgit-server as the `bale` user. setpriv exec's directly so the
# server is PID 1 of its process group and receives the container's signals.
# ---------------------------------------------------------------------------
log "starting baleforgit-server as bale user"
exec setpriv --reuid=bale --regid=bale --init-groups --inh-caps=-all \
    /usr/local/bin/baleforgit-server
