# Bundled image for the e2e harness: baleforgit-server + openssh-server + git
# + a fake `git-bale-authenticate` script that mints a forge-shaped JSON
# response. NOT for production — only `tests/e2e/run.py` should build it.

FROM rust:1.94-bookworm AS builder
WORKDIR /src

COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

RUN cargo build --release -p bale-server-bin \
 && strip target/release/baleforgit-server

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

COPY --from=builder /src/target/release/baleforgit-server /usr/local/bin/baleforgit-server
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

# Bind-mounts (data, git home) come from the host with UIDs mapped through
# rootless podman's user namespace, so the bare repo dirs can appear to be
# owned by a UID different from the `git` user that runs git-receive-pack
# inside the container. Git's "dubious ownership" check would then refuse
# every push. This is a test-only image; opt out of the check system-wide.
RUN printf '[safe]\n\tdirectory = *\n' > /etc/gitconfig

EXPOSE 8080 2222
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
