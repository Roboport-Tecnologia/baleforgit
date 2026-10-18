#!/bin/sh
# e2e container: ssh host keys, authorized_keys, bare repos and a fake
# git-bale-authenticate, then sshd + baleforgit-server side by side.

set -eu

log() { printf '[entrypoint] %s\n' "$*" >&2; }

# Bind-mounted /data is owned by the host (mapped) UID: hand it to `bale` so the
# server can write, and keep it 755 so the harness can walk it from the host.
if [ -d /data ]; then
    chown bale:bale /data
    chmod 755 /data
fi

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
[ -n "${BALE_DEFAULT_QUOTA_BYTES:-}" ] && export BALE_DEFAULT_QUOTA_BYTES
[ -n "${BALE_ADMIN_TOKEN_HEX:-}" ] && export BALE_ADMIN_TOKEN_HEX
[ -n "${RUST_LOG:-}" ] && export RUST_LOG
# Set by `run.py --meta postgres`; switches the server off the local SQLite meta.db.
[ -n "${BALE_POSTGRES_URL:-}" ] && export BALE_POSTGRES_URL
# Set by `run.py --coverage` so the instrumented server writes .profraw to the host.
[ -n "${LLVM_PROFILE_FILE:-}" ] && export LLVM_PROFILE_FILE
# Set by `run.py --backend s3`; a non-empty BALE_S3_BUCKET switches the blob store to S3.
for v in BALE_S3_BUCKET BALE_S3_ENDPOINT_URL BALE_S3_FORCE_PATH_STYLE \
         BALE_S3_ACCESS_KEY_ID BALE_S3_SECRET_ACCESS_KEY \
         BALE_S3_REGION BALE_S3_DISABLE_SSE BALE_S3_PREFIX \
         BALE_S3_SESSION_TOKEN; do
    eval "[ -n \"\${$v:-}\" ] && export $v" || true
done

# Fresh host keys every start; the harness disables StrictHostKeyChecking.
log "generating ssh host keys"
ssh-keygen -A >/dev/null

# /home/git is bind-mounted (bare repos survive restarts), which masks the .ssh
# dir baked into the image, so recreate it on every start.
mkdir -p /home/git/.ssh
printf '%s\n' "$SSH_AUTHORIZED_KEY" > /home/git/.ssh/authorized_keys
chown -R git:git /home/git
chmod 700 /home/git/.ssh
chmod 600 /home/git/.ssh/authorized_keys

# Bare repos at /home/git/<owner>/<repo>.git. The harness uses ssh:// URLs (they
# carry the port; scp-style can't), which git sends as the absolute path
# /<owner>/<repo>.git, hence the /<owner> symlink. The client splits the path on
# the first `/` into owner/repo, so owner must stay one segment deep.
for repo in $TEST_REPOS; do
    owner_dir=$(dirname "$repo")            # "e2e/repo" -> "e2e"
    repo_dir="/home/git/${repo}.git"        # /home/git/e2e/repo.git
    mkdir -p "$repo_dir"
    if [ ! -d "$repo_dir/objects" ]; then
        log "init bare repo $repo_dir"
        git init --bare --initial-branch=main "$repo_dir" >/dev/null
    fi
    chown -R git:git "/home/git/${owner_dir}"
    if [ ! -e "/${owner_dir}" ]; then
        ln -s "/home/git/${owner_dir}" "/${owner_dir}"
    fi
done

# Fake forge auth: returns the resolver's JSON shape (host-side `href` + hub bearer).
# Values are baked in now because the non-interactive ssh shell sources no rc files.
log "writing /usr/local/bin/git-bale-authenticate"
cat > /usr/local/bin/git-bale-authenticate <<EOF
#!/bin/sh
# owner/repo and upload|download args are ignored: BALE_GRANTS covers every repo.
printf '%s\n' '{"href":"${BALE_PUBLIC_HOST_URL}","Authorization":"Bearer ${E2E_HUB_TOKEN}"}'
EOF
chmod 755 /usr/local/bin/git-bale-authenticate

# StrictModes=no: on a Windows host the podman VM's bind mount can't hold Unix
# modes, so the chmod 600 above is a no-op and sshd would reject authorized_keys
# ("bad ownership or modes"), denying every publickey auth.
log "starting sshd on :2222"
/usr/sbin/sshd -D -e -o StrictModes=no &
SSHD_PID=$!

cleanup() {
    log "shutting down (sshd pid=$SSHD_PID)"
    kill "$SSHD_PID" 2>/dev/null || true
}
trap cleanup INT TERM EXIT

# exec so the server takes over this PID and receives the container's signals.
log "starting baleforgit-server as bale user"
exec setpriv --reuid=bale --regid=bale --init-groups --inh-caps=-all \
    /usr/local/bin/baleforgit-server
