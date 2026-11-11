#!/bin/bash
# Makes the server's own key for reading the private Vex1 repo (a GitHub "deploy key").
set -euo pipefail
K="$HOME/.ssh/vex1_deploy"
if [ ! -f "$K" ]; then
  ssh-keygen -q -t ed25519 -N '' -C "vex-micro deploy key" -f "$K"
fi
cat > "$HOME/.ssh/config" <<CFG
Host github-vex1
  HostName github.com
  User git
  IdentityFile $K
  IdentitiesOnly yes
CFG
chmod 600 "$HOME/.ssh/config"
echo "== done"
echo "DEPLOY KEY (public - safe to share): $(cat "$K.pub")"
