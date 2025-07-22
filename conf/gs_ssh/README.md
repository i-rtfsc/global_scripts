# SSH Security Guidelines
# 
# This directory contains SSH configuration templates.
# 
# IMPORTANT SECURITY NOTES:
# 1. Never commit private keys (id_rsa) to version control
# 2. Never commit actual SSH configs with sensitive information
# 3. Always use templates (.template files) for sharing configurations
# 
# Files in this directory:
# - *.template files: Safe to commit, contain examples and documentation
# - config, id_rsa, id_rsa.pub, known_hosts: Should NOT be committed
# 
# Setup Instructions:
# 1. Copy template files to actual filenames
# 2. Edit with your actual credentials/settings
# 3. Set proper permissions: chmod 600 id_rsa, chmod 644 id_rsa.pub
# 
# The .gitignore should exclude:
# - id_rsa
# - id_rsa.pub
# - config
# - config-vm
# - known_hosts
# - authorized_keys