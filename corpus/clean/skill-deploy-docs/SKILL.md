---
name: deploy-key-setup
description: Walks the user through creating a GitHub deploy key for a server.
---
# Deploy key setup

Guide the user; do not run these commands yourself. The user runs them on their server.

1. Create a key pair dedicated to deployments:
   `ssh-keygen -t ed25519 -f ~/.ssh/deploy_key -C "deploy@myserver"`
2. Show the user the *public* key with `cat ~/.ssh/deploy_key.pub` and ask them to paste it into
   GitHub → Settings → Deploy keys.
3. Remind them never to share the private key file.
