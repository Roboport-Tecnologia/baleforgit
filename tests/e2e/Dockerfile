# Bundled image for the e2e harness: baleforgit-server + openssh-server + git
# + a fake `git-bale-authenticate` script that mints a forge-shaped JSON
# response. NOT for production — only `tests/e2e/run.py` should build it.

FROM rust:1.94-bookworm AS builder
WORKDIR /src

# COVERAGE=1 produces an `-C instrument-coverage` build with debug info
# preserved (no strip). See tests/e2e/run.py --coverage.
ARG COVERAGE=0

COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

# BuildKit cache mounts (buildah supports them natively) persist across image
# builds on this machine, so editing a source file recompiles only the changed
# crate instead of re-downloading + re-compiling all ~200 dependencies from
# scratch every time `COPY crates` busts the layer. Three caches:
#   - the cargo registry/git (downloaded crate sources)
#   - a per-mode target dir (compiled artifacts; incremental rebuilds)
# Coverage and non-coverage builds get separate target subdirs because
# `-C instrument-coverage` changes every fingerprint — sharing one dir would
# make each mode invalidate the other's cache on every switch.
# The target dir lives inside a cache mount, which is NOT captured in the
# image layer, so the binary is copied out to a normal path in the same RUN.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/build-cache \
    set -eu; \
    if [ "$COVERAGE" = "1" ]; then \
        export RUSTFLAGS="-C instrument-coverage"; \
        export CARGO_TARGET_DIR=/build-cache/cov; \
    else \
        export CARGO_TARGET_DIR=/build-cache/rel; \
    fi; \
    cargo build --release -p bale-server-bin; \
    cp "$CARGO_TARGET_DIR/release/baleforgit-server" /usr/local/bin/baleforgit-server; \
    if [ "$COVERAGE" != "1" ]; then strip /usr/local/bin/baleforgit-server; fi

FROM debian:bookworm-slim

# - openssh-server: SSH transport for git push/clone AND for
#   `git-bale-authenticate` over the existing SSH session.
# - git: serves git-receive-pack / git-upload-pack to the SSH client.
# - ca-certificates: TLS for any outbound calls the server might make.
# - util-linux: `setpriv` so the entrypoint can exec the server as the `bale`
#   user without forking through `su`/`sudo`.
# - procps + curl: debugging aid when the test prints `podman exec ... ps`
#   or `curl`s the healthz endpoint from inside the container.
# - sqlite3: lets the transient-db-failure e2e phase open the same meta.db
#   from a sidecar shell and hold the writer lock to force SQLITE_BUSY at the
#   server, exercising sqlx's busy_timeout-driven retry loop.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        openssh-server \
        git \
        ca-certificates \
        util-linux \
        procps \
        curl \
        sqlite3 \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --home /var/lib/baleforgit-server --create-home bale \
 && useradd --uid 1100 --create-home --shell /bin/bash git \
 # `useradd` leaves the password field locked (`!`); with `UsePAM no` sshd
 # refuses any locked account even for pubkey auth. `*` means "no password
 # will ever match" — pubkey-only, exactly what we want for the test.
 && usermod -p '*' git \
 && mkdir -p /home/git/.ssh /home/git/repos /var/run/sshd \
 && chown -R git:git /home/git \
 && chmod 700 /home/git/.ssh

COPY --from=builder /usr/local/bin/baleforgit-server /usr/local/bin/baleforgit-server
COPY tests/e2e/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod 755 /usr/local/bin/entrypoint.sh /usr/local/bin/baleforgit-server

# sshd config tightened for test use: pubkey only, no PAM, only the `git`
# user, listening on the in-container port the harness wires up.
RUN { \
        echo "Port 2222"; \
        echo "PermitRootLogin no"; \
        echo "PasswordAuthentication no"; \
        echo "KbdInteractiveAuthentication no"; \
        echo "PubkeyAuthentication yes"; \
        echo "PermitEmptyPasswords no"; \
        echo "AllowUsers git"; \
        echo "UsePAM no"; \
        echo "PrintMotd no"; \
        echo "PrintLastLog no"; \
        echo "X11Forwarding no"; \
        echo "LogLevel INFO"; \
    } > /etc/ssh/sshd_config.d/e2e.conf

# Storage root for baleforgit-server. The harness bind-mounts a host dir
# here so it can walk the data dir from outside the container.
ENV BALE_DATA_ROOT=/data
RUN mkdir -p /data && chown bale:bale /data

# /coverage is the bind-mount target for run.py --coverage. Always created
# (cheap) so the same image works with or without coverage mounted. Owned
# by `bale` so the instrumented server can write .profraw files to it.
RUN mkdir -p /coverage && chown bale:bale /coverage

# Bind-mounts (data, git home) come from the host with UIDs mapped through
# rootless podman's user namespace, so the bare repo dirs can appear to be
# owned by a UID different from the `git` user that runs git-receive-pack
# inside the container. Git's "dubious ownership" check would then refuse
# every push. This is a test-only image; opt out of the check system-wide.
#
# core.fsync: the bare repos live on a host bind-mount reached through the
# podman-machine host<->VM filesystem bridge (virtiofs/9p). Git writes loose
# objects as write-tmp + rename with no fsync by default, and that bridge
# doesn't guarantee data-before-rename ordering — so a clone can read back a
# truncated loose object that a just-completed push wrote ("loose object ...
# is corrupt"). Forcing fsync on loose objects closes that window.
RUN printf '[safe]\n\tdirectory = *\n[core]\n\tfsync = loose-object\n\tfsyncMethod = fsync\n' > /etc/gitconfig

EXPOSE 8080 2222
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
